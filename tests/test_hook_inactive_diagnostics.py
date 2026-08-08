from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hook_monitor.runtime.storage import EventStore
from tooluseproxy.integrations.codex import run_codex_hook


REPO_ROOT = Path(__file__).parents[1]
HOOK_LAUNCHER = REPO_ROOT / "hooks" / "run_hook.sh"
PROTECTED_SENTINEL = "INACTIVE.DIAGNOSTIC.MUST.NOT.LEAK.4F9C"
PHASES = (
    ("pre-tool-use", "PreToolUse"),
    ("post-tool-use", "PostToolUse"),
    ("stop", "Stop"),
)


class HookInactiveDiagnosticTest(unittest.TestCase):
    def test_permission_hardening_failure_preserves_single_deny_output(
        self,
    ) -> None:
        deny = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "protected content blocked",
            }
        }
        stdout = io.StringIO()
        stderr = io.StringIO()

        def render_deny(*_: object, **__: object) -> int:
            print(json.dumps(deny))
            return 0

        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            mock.patch(
                "tooluseproxy.integrations.codex.run_hook",
                side_effect=render_deny,
            ),
            mock.patch(
                "tooluseproxy.integrations.codex."
                "secure_database_permissions",
                side_effect=OSError(PROTECTED_SENTINEL),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(
                0,
                run_codex_hook(
                    "pre-tool-use",
                    data_dir=Path(temporary_directory),
                ),
            )

        self.assertEqual(deny, json.loads(stdout.getvalue()))
        self.assertEqual(1, stdout.getvalue().count("\n"))
        self.assertNotIn("runtime_error", stdout.getvalue())
        self.assertNotIn(PROTECTED_SENTINEL, stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_invalid_partial_hook_output_is_replaced_not_concatenated(
        self,
    ) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        def render_invalid(*_: object, **__: object) -> int:
            print(f'{{"partial":"{PROTECTED_SENTINEL}"')
            return 0

        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            mock.patch(
                "tooluseproxy.integrations.codex.run_hook",
                side_effect=render_invalid,
            ),
            mock.patch(
                "tooluseproxy.integrations.codex."
                "secure_database_permissions",
                side_effect=OSError(PROTECTED_SENTINEL),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(
                0,
                run_codex_hook(
                    "pre-tool-use",
                    data_dir=Path(temporary_directory),
                ),
            )

        output = json.loads(stdout.getvalue())
        self.assertIn(
            "runtime_error",
            self._diagnostic_message(output, "PreToolUse"),
        )
        self.assertEqual(1, stdout.getvalue().count("\n"))
        self.assertNotIn(PROTECTED_SENTINEL, stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_top_level_runtime_error_uses_phase_specific_json_without_exception(
        self,
    ) -> None:
        for phase, hook_event in PHASES:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch(
                    "tooluseproxy.integrations.codex.resolve_runtime_paths",
                    side_effect=RuntimeError(PROTECTED_SENTINEL),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(0, run_codex_hook(phase))

            output = json.loads(stdout.getvalue())
            message = self._diagnostic_message(output, hook_event)
            self.assertIn("runtime_error", message)
            self.assertNotIn(PROTECTED_SENTINEL, stdout.getvalue())
            self.assertEqual("", stderr.getvalue())
            self._assert_nonblocking(output, hook_event)

    def test_missing_database_uses_phase_specific_json_without_stdin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "data"
            for phase, hook_event in PHASES:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tooluseproxy",
                        "hook",
                        phase,
                        "--data-dir",
                        str(data_dir),
                    ],
                    cwd=REPO_ROOT,
                    input=self._payload(hook_event),
                    capture_output=True,
                    text=True,
                    check=True,
                )

                output = json.loads(result.stdout)
                message = self._diagnostic_message(output, hook_event)
                self.assertIn("database_missing", message)
                self.assertNotIn(PROTECTED_SENTINEL, result.stdout)
                self.assertEqual("", result.stderr)
                self._assert_nonblocking(output, hook_event)

            self.assertFalse((data_dir / "events.db").exists())

    def test_invalid_payload_uses_phase_specific_json_without_payload(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "data"
            data_dir.mkdir()
            EventStore(data_dir / "events.db").initialize()
            for phase, hook_event in PHASES:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "tooluseproxy",
                        "hook",
                        phase,
                        "--data-dir",
                        str(data_dir),
                    ],
                    cwd=REPO_ROOT,
                    input=f'{{"secret":"{PROTECTED_SENTINEL}"',
                    capture_output=True,
                    text=True,
                    check=True,
                )

                output = json.loads(result.stdout)
                message = self._diagnostic_message(output, hook_event)
                self.assertIn("hook_payload_invalid", message)
                self.assertNotIn(PROTECTED_SENTINEL, result.stdout)
                self.assertEqual("", result.stderr)
                self._assert_nonblocking(output, hook_event)

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_missing_plugin_environment_uses_phase_specific_json(
        self,
    ) -> None:
        environment = {
            "PATH": os.environ.get("PATH", ""),
        }
        for phase, hook_event in PHASES:
            result = subprocess.run(
                ["/bin/sh", str(HOOK_LAUNCHER), phase],
                cwd=REPO_ROOT,
                env=environment,
                input=self._payload(hook_event),
                capture_output=True,
                text=True,
                check=True,
            )

            output = json.loads(result.stdout)
            message = self._diagnostic_message(output, hook_event)
            self.assertEqual(
                (
                    "ToolUseProxy inactive (plugin_environment): "
                    "PLUGIN_ROOT and PLUGIN_DATA are required"
                ),
                message,
            )
            self.assertNotIn(PROTECTED_SENTINEL, result.stdout)
            self.assertEqual("", result.stderr)
            self._assert_nonblocking(output, hook_event)

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_missing_python_uses_phase_specific_json_without_stdin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "data"
            environment = {
                "PATH": "",
                "PLUGIN_ROOT": str(REPO_ROOT),
                "PLUGIN_DATA": str(data_dir),
            }
            for phase, hook_event in PHASES:
                result = subprocess.run(
                    ["/bin/sh", str(HOOK_LAUNCHER), phase],
                    cwd=REPO_ROOT,
                    env=environment,
                    input=self._payload(hook_event),
                    capture_output=True,
                    text=True,
                    check=True,
                )

                output = json.loads(result.stdout)
                message = self._diagnostic_message(output, hook_event)
                self.assertEqual(
                    (
                        "ToolUseProxy inactive (python_missing): "
                        "Python 3.11 or 3.12 is required"
                    ),
                    message,
                )
                self.assertNotIn(PROTECTED_SENTINEL, result.stdout)
                self.assertEqual("", result.stderr)
                self._assert_nonblocking(output, hook_event)

            self.assertFalse((data_dir / "events.db").exists())

    @unittest.skipIf(os.name == "nt", "POSIX launcher test")
    def test_runtime_start_failure_uses_json_and_discards_raw_stderr(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fake_python = root / "python"
            fake_python.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-c\" ]; then exit 0; fi\n"
                f"printf '%s\\n' '{PROTECTED_SENTINEL}' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o700)
            environment = {
                "PATH": "",
                "PLUGIN_ROOT": str(REPO_ROOT),
                "PLUGIN_DATA": str(root / "data"),
                "TOOLUSEPROXY_PYTHON": str(fake_python),
            }
            for phase, hook_event in PHASES:
                result = subprocess.run(
                    ["/bin/sh", str(HOOK_LAUNCHER), phase],
                    cwd=REPO_ROOT,
                    env=environment,
                    input=self._payload(hook_event),
                    capture_output=True,
                    text=True,
                    check=True,
                )

                output = json.loads(result.stdout)
                message = self._diagnostic_message(output, hook_event)
                self.assertIn("runtime_start_failed", message)
                self.assertNotIn(PROTECTED_SENTINEL, result.stdout)
                self.assertEqual("", result.stderr)
                self._assert_nonblocking(output, hook_event)

    @staticmethod
    def _payload(hook_event: str) -> str:
        return json.dumps(
            {
                "hook_event_name": hook_event,
                "tool_input": {"value": PROTECTED_SENTINEL},
                "last_assistant_message": PROTECTED_SENTINEL,
            }
        )

    @staticmethod
    def _diagnostic_message(
        output: dict[str, object],
        hook_event: str,
    ) -> str:
        if hook_event == "Stop":
            message = output.get("systemMessage")
        else:
            hook_output = output.get("hookSpecificOutput")
            if not isinstance(hook_output, dict):
                raise AssertionError("hookSpecificOutput is missing")
            if hook_output.get("hookEventName") != hook_event:
                raise AssertionError("hookEventName does not match the phase")
            message = hook_output.get("additionalContext")
        if not isinstance(message, str):
            raise AssertionError("diagnostic message is missing")
        return message

    @staticmethod
    def _assert_nonblocking(
        output: dict[str, object],
        hook_event: str,
    ) -> None:
        self_keys = set(output)
        if hook_event == "Stop":
            if self_keys != {"systemMessage"}:
                raise AssertionError("Stop diagnostic must be advisory only")
            return
        if self_keys != {"hookSpecificOutput"}:
            raise AssertionError("tool diagnostic must be advisory only")
        hook_output = output["hookSpecificOutput"]
        if not isinstance(hook_output, dict):
            raise AssertionError("hookSpecificOutput must be an object")
        forbidden = {
            "permissionDecision",
            "permissionDecisionReason",
            "decision",
            "updatedInput",
        }
        if forbidden.intersection(hook_output):
            raise AssertionError("inactive diagnostic must not block or rewrite")


if __name__ == "__main__":
    unittest.main()
