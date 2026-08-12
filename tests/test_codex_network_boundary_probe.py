from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.probe_codex_network_boundary import (
    ProbeError,
    probe_codex_network_boundary,
    render_probe_report,
)


def _request_params() -> dict[str, object]:
    return {
        "required": ["itemId", "startedAtMs", "threadId", "turnId"],
        "properties": {"networkApprovalContext": {}},
        "definitions": {
            "NetworkApprovalContext": {
                "required": ["host", "protocol"],
                "properties": {"host": {"type": "string"}, "protocol": {}},
            }
        },
    }


def _response_schema() -> dict[str, object]:
    return {
        "definitions": {
            "CommandExecutionApprovalDecision": {
                "oneOf": [
                    {"enum": ["accept"]},
                    {"enum": ["acceptForSession"]},
                    {"enum": ["decline"]},
                    {"enum": ["cancel"]},
                    {"properties": {"applyNetworkPolicyAmendment": {}}},
                ]
            }
        }
    }


class CodexNetworkBoundaryProbeTest(unittest.TestCase):
    def test_candidate_contract_is_detected_without_exposing_paths(self) -> None:
        sensitive_binary_path = "/private/sensitive/codex"
        calls: list[list[str]] = []

        def fake_run(
            argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            del kwargs
            calls.append(argv)
            if argv[1:] == ["--version"]:
                stdout = "codex-cli 0.145.0\n"
            elif argv[1:] == ["features", "list"]:
                stdout = "network_proxy experimental false\n"
            else:
                output_root = Path(argv[-1])
                (output_root / "CommandExecutionRequestApprovalParams.json").write_text(
                    json.dumps(_request_params()), encoding="utf-8"
                )
                (output_root / "CommandExecutionRequestApprovalResponse.json").write_text(
                    json.dumps(_response_schema()), encoding="utf-8"
                )
                (output_root / "ServerRequest.json").write_text(
                    json.dumps({"enum": ["item/commandExecution/requestApproval"]}),
                    encoding="utf-8",
                )
                stdout = ""
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        with patch("scripts.probe_codex_network_boundary.subprocess.run", fake_run):
            report = probe_codex_network_boundary(sensitive_binary_path)

        serialized = json.dumps(report, sort_keys=True)
        rendered = render_probe_report(report)
        self.assertTrue(report["summary"]["candidate_contract_available"])
        self.assertEqual("experimental", report["codex"]["network_proxy"]["stage"])
        self.assertFalse(report["codex"]["network_proxy"]["enabled"])
        self.assertFalse(report["privacy"]["network_executed"])
        self.assertFalse(report["summary"]["production_integration_enabled"])
        self.assertEqual(
            [
                [sensitive_binary_path, "--version"],
                [sensitive_binary_path, "features", "list"],
            ],
            calls[:2],
        )
        self.assertEqual(
            [
                sensitive_binary_path,
                "app-server",
                "generate-json-schema",
                "--experimental",
                "--out",
            ],
            calls[2][:-1],
        )
        self.assertEqual(3, len(calls))
        self.assertNotIn(sensitive_binary_path, serialized)
        self.assertNotIn(sensitive_binary_path, rendered)

    def test_missing_network_context_is_not_a_candidate(self) -> None:
        def fake_run(
            argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            del kwargs
            if argv[1:] == ["--version"]:
                stdout = "codex-cli 0.145.0\n"
            elif argv[1:] == ["features", "list"]:
                stdout = "network_proxy experimental false\n"
            else:
                output_root = Path(argv[-1])
                params = _request_params()
                params["properties"] = {}
                (output_root / "CommandExecutionRequestApprovalParams.json").write_text(
                    json.dumps(params), encoding="utf-8"
                )
                (output_root / "CommandExecutionRequestApprovalResponse.json").write_text(
                    json.dumps(_response_schema()), encoding="utf-8"
                )
                (output_root / "ServerRequest.json").write_text(
                    json.dumps({"enum": ["item/commandExecution/requestApproval"]}),
                    encoding="utf-8",
                )
                stdout = ""
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        with patch("scripts.probe_codex_network_boundary.subprocess.run", fake_run):
            report = probe_codex_network_boundary("codex")

        self.assertFalse(report["summary"]["candidate_contract_available"])

    def test_nonzero_codex_exit_is_sanitized(self) -> None:
        completed = subprocess.CompletedProcess(
            ["codex", "--version"],
            9,
            stdout="",
            stderr="sensitive diagnostic",
        )
        with patch(
            "scripts.probe_codex_network_boundary.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(ProbeError, "exit code 9") as context:
                probe_codex_network_boundary("codex")

        self.assertNotIn("sensitive diagnostic", str(context.exception))

    def test_schema_size_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            oversized = Path(temporary_directory) / "schema.json"
            oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            from scripts.probe_codex_network_boundary import _load_schema

            with self.assertRaisesRegex(ProbeError, "too large"):
                _load_schema(oversized)


if __name__ == "__main__":
    unittest.main()
