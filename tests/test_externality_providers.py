from __future__ import annotations

import json
import os
import ast
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import hook_monitor.externality.providers as externality_providers

from hook_monitor.externality.models import ExternalityEnvelope, ExternalityVerdict
from hook_monitor.externality.providers import (
    CODEX_DISABLED_FEATURES,
    CodexExecJudge,
    CodexJudgeRunner,
    JudgeProviderError,
    JudgeObservation,
    ProcessResult,
    CodexExecutableIdentity,
    build_codex_probe_receipt,
    build_codex_exec_argv,
    codex_events_contain_tool_activity,
    resolve_codex_executable_identity,
    verify_codex_probe_receipt,
    write_codex_probe_receipt,
)


def _envelope() -> ExternalityEnvelope:
    return ExternalityEnvelope.create(
        tool_family="bash",
        analysis_coverage="partial",
        executable_classes={"python_runtime"},
        capabilities={"child_process"},
        risk_signals={"dynamic_code"},
        counts={"segment_count": 1},
    )


class CodexExecJudgeTest(unittest.TestCase):
    def test_codex_identity_requires_supported_version_and_is_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            executable = Path(temporary_directory) / "codex"
            executable.write_bytes(b"codex-test-binary")
            executable.chmod(0o700)
            with patch(
                "hook_monitor.externality.providers.shutil.which",
                return_value=str(executable),
            ), patch(
                "hook_monitor.externality.providers.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [str(executable), "--version"],
                    0,
                    stdout=b"codex-cli 0.144.9\n",
                    stderr=b"",
                ),
            ):
                with self.assertRaisesRegex(
                    JudgeProviderError, "codex_version_unsupported"
                ):
                    resolve_codex_executable_identity("codex")

            executable.write_bytes(b"codex-test-binary-supported")
            with patch(
                "hook_monitor.externality.providers.shutil.which",
                return_value=str(executable),
            ), patch(
                "hook_monitor.externality.providers.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [str(executable), "--version"],
                    0,
                    stdout=b"codex-cli 0.145.0\n",
                    stderr=b"",
                ),
            ) as version_call:
                first = resolve_codex_executable_identity("codex")
                second = resolve_codex_executable_identity("codex")

            self.assertEqual("codex-cli 0.145.0", first.version)
            self.assertEqual(first, second)
            self.assertEqual(1, version_call.call_count)

    def test_provider_module_has_no_direct_http_or_api_key_contract(self) -> None:
        provider_path = (
            Path(__file__).resolve().parents[1]
            / "hook_monitor"
            / "externality"
            / "providers.py"
        )
        source = provider_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse({"urllib", "urllib.request", "httpx", "requests"} & imports)
        self.assertNotIn("api.openai.com", source)
        self.assertNotIn("API_KEY", source)
        self.assertNotIn("Authorization", source)

    def test_codex_child_environment_does_not_forward_api_credentials(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-be-forwarded",
                "TOOLUSEPROXY_JUDGE_OPENAI_API_KEY": "must-not-be-forwarded",
                "CODEX_HOME": "/test/codex-home",
                "PATH": "/test/bin",
            },
            clear=True,
        ):
            environment = externality_providers._minimal_codex_environment()

        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("TOOLUSEPROXY_JUDGE_OPENAI_API_KEY", environment)
        self.assertEqual("/test/codex-home", environment["CODEX_HOME"])

    def test_runner_uses_one_codex_provider_and_has_no_fallback(self) -> None:
        class FailedCodex:
            timeout_seconds = 7.0

            def __init__(self) -> None:
                self.calls = 0

            def judge_with_timeout(self, _envelope, timeout):  # type: ignore[no-untyped-def]
                self.calls += 1
                self.timeout = timeout
                raise JudgeProviderError("codex_exec_timeout")

        provider = FailedCodex()
        result = CodexJudgeRunner(  # type: ignore[arg-type]
            provider,
            total_timeout_seconds=7.0,
        ).judge(_envelope())

        self.assertEqual(1, provider.calls)
        self.assertIsNone(result.observation)
        self.assertEqual(("codex_exec_timeout",), result.failure_codes)

    def test_each_judgment_uses_a_fresh_ephemeral_directory(self) -> None:
        roots: list[Path] = []

        def runner(argv, stdin, cwd, environment, timeout):  # type: ignore[no-untyped-def]
            del stdin, environment, timeout
            roots.append(cwd)
            self.assertIn("--ephemeral", argv)
            output_path = Path(argv[argv.index("--output-last-message") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "unknown",
                        "confidence": "low",
                        "reason_codes": ["insufficient_evidence"],
                    }
                ),
                encoding="utf-8",
            )
            return ProcessResult(
                0,
                b'{"type":"thread.started"}\n{"type":"turn.completed"}\n',
                b"",
            )

        judge = CodexExecJudge(runner=runner)
        judge.judge(_envelope())
        judge.judge(_envelope())

        self.assertEqual(2, len(roots))
        self.assertNotEqual(roots[0], roots[1])

    def test_argv_uses_ephemeral_read_only_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            argv = build_codex_exec_argv(
                executable="codex",
                schema_path=root / "schema.json",
                output_path=root / "output.json",
                model=None,
            )

        self.assertIn("--ephemeral", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("--strict-config", argv)
        self.assertEqual("read-only", argv[argv.index("--sandbox") + 1])
        self.assertEqual("-", argv[-1])
        disabled = {
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--disable"
        }
        self.assertEqual(set(CODEX_DISABLED_FEATURES), disabled)
        self.assertTrue({"hooks", "plugins", "shell_tool", "browser_use"} <= disabled)

    def test_probe_accepts_only_schema_output_without_tool_events(self) -> None:
        def runner(argv, stdin, cwd, environment, timeout):  # type: ignore[no-untyped-def]
            del cwd, environment, timeout
            output_path = Path(argv[argv.index("--output-last-message") + 1])
            is_risky = b'"child_process"' in stdin
            output_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "possibly_external" if is_risky else "local",
                        "confidence": "high",
                        "reason_codes": [
                            "network_capable_child_process"
                            if is_risky
                            else "known_local_only"
                        ],
                    }
                ),
                encoding="utf-8",
            )
            events = b'{"type":"thread.started"}\n{"type":"turn.completed"}\n'
            return ProcessResult(0, events, b"")

        probe = CodexExecJudge(runner=runner).probe()

        self.assertTrue(probe.eligible)
        self.assertEqual((), probe.reason_codes)
        self.assertEqual("local", probe.local_observation.verdict.verdict)
        self.assertEqual("possibly_external", probe.risky_observation.verdict.verdict)

    def test_probe_rejects_tool_activity_or_unexpected_files(self) -> None:
        def runner(argv, stdin, cwd, environment, timeout):  # type: ignore[no-untyped-def]
            del environment, timeout
            output_path = Path(argv[argv.index("--output-last-message") + 1])
            is_risky = b'"child_process"' in stdin
            output_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "possibly_external" if is_risky else "local",
                        "confidence": "high",
                        "reason_codes": [
                            "network_capable_child_process"
                            if is_risky
                            else "known_local_only"
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (cwd / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            events = b'{"type":"item.completed","item":{"type":"command_execution"}}\n'
            return ProcessResult(0, events, b"")

        probe = CodexExecJudge(runner=runner).probe()

        self.assertFalse(probe.eligible)
        self.assertEqual(
            ("tool_activity_observed", "unexpected_files_written"),
            probe.reason_codes,
        )

    def test_event_parser_rejects_invalid_or_tool_event_json(self) -> None:
        self.assertTrue(codex_events_contain_tool_activity(b"not-json\n"))
        self.assertTrue(
            codex_events_contain_tool_activity(
                b'{"type":"item.completed","item":{"type":"web_search"}}\n'
            )
        )
        self.assertFalse(
            codex_events_contain_tool_activity(
                b'{"type":"thread.started"}\n{"type":"turn.completed"}\n'
            )
        )

    def test_probe_receipt_is_identity_bound_mode_0600_and_stale_safe(self) -> None:
        local = JudgeObservation(
            provider="codex_exec",
            model="codex_default",
            envelope_sha256="1" * 64,
            latency_ms=1,
            verdict=ExternalityVerdict(
                verdict="local",
                confidence="high",
                reason_codes=("known_local_only",),
            ),
        )
        risky = JudgeObservation(
            provider="codex_exec",
            model="codex_default",
            envelope_sha256="2" * 64,
            latency_ms=1,
            verdict=ExternalityVerdict(
                verdict="possibly_external",
                confidence="high",
                reason_codes=("network_capable_child_process",),
            ),
        )
        from hook_monitor.externality.providers import CodexCapabilityProbe

        probe = CodexCapabilityProbe(True, (), local, risky)
        identity = CodexExecutableIdentity(
            executable_path="/test/codex",
            version="codex-cli test",
            binary_sha256="3" * 64,
            path_sha256="4" * 64,
        )
        receipt = build_codex_probe_receipt(
            probe,
            identity=identity,
            model=None,
            checked_at="2026-08-12T00:00:00+00:00",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "receipt.json"
            write_codex_probe_receipt(path, receipt)
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
            self.assertEqual(
                (True, None),
                verify_codex_probe_receipt(
                    path,
                    identity=identity,
                    model=None,
                    now=datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
                ),
            )
            stale = CodexExecutableIdentity(
                executable_path=identity.executable_path,
                version=identity.version,
                binary_sha256="5" * 64,
                path_sha256=identity.path_sha256,
            )
            self.assertEqual(
                (False, "codex_probe_receipt_stale"),
                verify_codex_probe_receipt(
                    path,
                    identity=stale,
                    model=None,
                    now=datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
                ),
            )
            self.assertEqual(
                (False, "codex_probe_receipt_stale"),
                verify_codex_probe_receipt(
                    path,
                    identity=identity,
                    model=None,
                    now=datetime(2026, 8, 14, tzinfo=timezone.utc),
                ),
            )


if __name__ == "__main__":
    unittest.main()
