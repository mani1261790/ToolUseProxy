from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from hook_monitor.externality.models import ExternalityVerdict
from hook_monitor.externality.providers import JudgeChainResult, JudgeObservation
from hook_monitor.runtime.externality_shadow import (
    build_externality_shadow_report,
    list_externality_shadow_observations,
    observe_externality_shadow,
    store_externality_shadow_observation,
)
from hook_monitor.runtime.parser import normalize_event
from hook_monitor.runtime.runner import run_hook
from hook_monitor.runtime.settings import (
    EXTERNALITY_PROTECTION_KEY,
    PRE_TOOL_POLICY_KEY,
)
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace


REPO_ROOT = Path(__file__).resolve().parents[1]


class _FakeChain:
    def __init__(self, result: JudgeChainResult) -> None:
        self.result = result
        self.calls = 0

    def judge(self, _envelope):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.result.observation is None:
            return self.result
        return replace(
            self.result,
            observation=replace(
                self.result.observation,
                envelope_sha256=_envelope.digest_sha256(),
            ),
        )


def _event(root: Path, command: str, *, event_id: str = "event-pre"):
    return normalize_event(
        "pre_tool_use",
        {
            "session_id": "session",
            "turn_id": "turn",
            "tool_use_id": "tool-use",
            "tool_name": "Bash",
            "cwd": str(root),
            "tool_input": {"command": command},
        },
        workspace_root=str(root),
    )


class ExternalityShadowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workspace"
        self.root.mkdir()
        self.db_path = Path(self.temporary.name) / "events.db"
        EventStore(self.db_path).initialize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_known_adapter_external_does_not_call_judge(self) -> None:
        canary = "PRIVATE_CURL_CANARY_650b"
        with patch(
            "hook_monitor.runtime.externality_shadow.resolve_judge_configuration"
        ) as resolver:
            observation = observe_externality_shadow(
                _event(
                    self.root,
                    f"curl --data {canary} https://example.invalid",
                ),
                workspace_root=self.root,
                environ={"TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": "fake"},
            )

        assert observation is not None
        resolver.assert_not_called()
        self.assertEqual("external", observation.adapter_verdict)
        self.assertEqual("external", observation.shadow_verdict)
        self.assertEqual("not_needed", observation.judge_status)
        self.assertNotIn(canary, repr(observation))
        self.assertNotIn("example.invalid", repr(observation))

    def test_unknown_static_call_uses_judge_and_stores_only_hashes(self) -> None:
        canary = "PRIVATE_CUSTOM_CANARY_a739"
        event = _event(self.root, f"./custom-agent --secret {canary}")
        chain = _FakeChain(
            JudgeChainResult(
                JudgeObservation(
                    provider="codex_exec",
                    model="private-model-name",
                    envelope_sha256="0" * 64,
                    latency_ms=3,
                    verdict=ExternalityVerdict(
                        verdict="possibly_external",
                        confidence="low",
                        reason_codes=("opaque_executable",),
                    ),
                ),
                (),
            )
        )
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_shadow.resolve_judge_configuration",
            return_value=configuration,
        ):
            observation = observe_externality_shadow(
                event,
                workspace_root=self.root,
                environ={},
            )
        assert observation is not None
        store_externality_shadow_observation(self.db_path, observation)
        stored = list_externality_shadow_observations(self.db_path)

        self.assertEqual(1, chain.calls)
        self.assertEqual("possibly_external", stored[0].shadow_verdict)
        serialized = repr(stored)
        self.assertNotIn(canary, serialized)
        self.assertNotIn("custom-agent", serialized)
        self.assertNotIn("private-model-name", serialized)

        with sqlite3.connect(self.db_path) as conn:
            columns = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(externality_shadow_observations)"
                )
            }
        self.assertFalse(
            columns
            & {"raw_command", "payload", "url", "host", "path", "source_id"}
        )

    def test_failure_is_unknown_and_never_local(self) -> None:
        chain = _FakeChain(JudgeChainResult(None, ("provider_timeout",)))
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_shadow.resolve_judge_configuration",
            return_value=configuration,
        ):
            observation = observe_externality_shadow(
                _event(self.root, "./opaque"),
                workspace_root=self.root,
                environ={},
            )

        assert observation is not None
        self.assertEqual("failed", observation.judge_status)
        self.assertEqual("failed", observation.judge_verdict)
        self.assertEqual("unknown", observation.shadow_verdict)
        self.assertEqual("provider_timeout", observation.failure_code)

    def test_replay_decision_is_immutable_but_timing_is_first_write_wins(self) -> None:
        observation = observe_externality_shadow(
            _event(self.root, "rg TODO ."),
            workspace_root=self.root,
            environ={},
        )
        assert observation is not None
        store_externality_shadow_observation(self.db_path, observation)
        store_externality_shadow_observation(
            self.db_path,
            replace(observation, static_duration_ms=999.0),
        )
        conflicting = replace(observation, tool_use_id="other-tool-use")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "replay mismatch"):
            store_externality_shadow_observation(self.db_path, conflicting)

        stored = list_externality_shadow_observations(self.db_path)
        self.assertEqual(observation.static_duration_ms, stored[0].static_duration_ms)

    def test_invalid_or_inconsistent_observation_is_rejected_before_storage(self) -> None:
        observation = observe_externality_shadow(
            _event(self.root, "rg TODO ."),
            workspace_root=self.root,
            environ={},
        )
        assert observation is not None
        invalid = (
            replace(observation, provider="arbitrary_provider"),
            replace(observation, analysis_coverage="broad"),
            replace(observation, capability_count=True),
            replace(observation, observation_id="f" * 64),
            replace(observation, judge_status="completed"),
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    store_externality_shadow_observation(self.db_path, value)

    def test_stored_observation_is_immutable(self) -> None:
        observation = observe_externality_shadow(
            _event(self.root, "rg TODO ."),
            workspace_root=self.root,
            environ={},
        )
        assert observation is not None
        store_externality_shadow_observation(self.db_path, observation)

        with sqlite3.connect(self.db_path) as conn:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                conn.execute(
                    "UPDATE externality_shadow_observations "
                    "SET shadow_verdict = 'unknown'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                conn.execute("DELETE FROM externality_shadow_observations")

    def test_missing_shadow_schema_is_not_created_by_hook_storage(self) -> None:
        observation = observe_externality_shadow(
            _event(self.root, "rg TODO ."),
            workspace_root=self.root,
            environ={},
        )
        assert observation is not None
        missing_schema_db = Path(self.temporary.name) / "missing-shadow.db"
        with sqlite3.connect(missing_schema_db) as conn:
            conn.execute("CREATE TABLE marker (id INTEGER)")

        with self.assertRaisesRegex(RuntimeError, "schema mismatch"):
            store_externality_shadow_observation(missing_schema_db, observation)
        with sqlite3.connect(missing_schema_db) as conn:
            exists = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'table' AND name = 'externality_shadow_observations'"
            ).fetchone()[0]
        self.assertEqual(0, exists)

    def test_mismatched_provider_observation_fails_closed(self) -> None:
        chain = _FakeChain(
            JudgeChainResult(
                JudgeObservation(
                    provider="codex_exec",
                    model="test-model",
                    envelope_sha256="0" * 64,
                    latency_ms=3,
                    verdict=ExternalityVerdict(
                        verdict="local",
                        confidence="high",
                        reason_codes=("known_local_only",),
                    ),
                ),
                (),
            )
        )
        chain.judge = lambda _envelope: chain.result  # type: ignore[method-assign]
        configuration = type(
            "Configuration",
            (),
            {"status": "ready", "chain": chain, "failure_code": None},
        )()
        with patch(
            "hook_monitor.runtime.externality_shadow.resolve_judge_configuration",
            return_value=configuration,
        ):
            observation = observe_externality_shadow(
                _event(self.root, "./opaque"),
                workspace_root=self.root,
                environ={},
            )

        assert observation is not None
        self.assertEqual("failed", observation.judge_status)
        self.assertEqual("provider_observation_invalid", observation.failure_code)
        self.assertEqual("unknown", observation.shadow_verdict)

    def test_report_is_aggregate_and_production_behavior_is_unchanged(self) -> None:
        local = observe_externality_shadow(
            _event(self.root, "rg TODO .", event_id="local"),
            workspace_root=self.root,
            environ={},
        )
        unknown = observe_externality_shadow(
            _event(self.root, "./opaque", event_id="unknown"),
            workspace_root=self.root,
            environ={},
        )
        assert local is not None and unknown is not None
        report = build_externality_shadow_report((local, unknown))

        self.assertEqual(2, report["observation_count"])
        self.assertEqual({"local": 1, "unknown": 1}, report["shadow_verdict"])
        self.assertFalse(report["production_behavior_changed"])
        self.assertEqual(0, report["privacy"]["raw_value_fields"])
        self.assertNotIn("event", repr(report))

    def test_report_cli_is_value_free(self) -> None:
        observation = observe_externality_shadow(
            _event(self.root, "./opaque"),
            workspace_root=self.root,
            environ={},
        )
        assert observation is not None
        store_externality_shadow_observation(self.db_path, observation)
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "report_externality_shadow.py"),
                "--db",
                str(self.db_path),
            ],
            cwd=REPO_ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(1, report["observation_count"])
        self.assertNotIn("event-pre", result.stdout)
        self.assertNotIn("opaque", result.stdout)


class ExternalityShadowHookIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.db_path = root / "events.db"
        self.store = EventStore(self.db_path)
        self.store.initialize()
        workspace = resolve_workspace(
            str(self.workspace),
            str(self.workspace),
            discovered_by="test",
        )
        self.store.register_workspace(workspace)
        assert workspace.workspace_id is not None
        initial = self.store.get_workspace_runtime_settings(workspace.workspace_id)
        self.store.apply_workspace_runtime_settings_profile(
            workspace,
            settings={
                PRE_TOOL_POLICY_KEY: True,
                EXTERNALITY_PROTECTION_KEY: True,
            },
            expected_revision=initial.revision,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_shadow_does_not_change_hook_stdout(self) -> None:
        payload = {
            "session_id": "session-hook",
            "turn_id": "turn-hook",
            "tool_use_id": "tool-hook",
            "tool_name": "Bash",
            "cwd": str(self.workspace),
            "tool_input": {"command": "./opaque"},
        }
        stdin = type("FakeStdin", (), {"buffer": __import__("io").BytesIO(json.dumps(payload).encode())})()
        with patch("sys.stdin", stdin), patch.dict(
            os.environ,
            {
                "TOOLUSEPROXY_WORKSPACE_ROOT": str(self.workspace),
                "TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": "off",
            },
            clear=False,
        ), patch("sys.stdout", new_callable=__import__("io").StringIO) as stdout:
            exit_code = run_hook(
                "pre_tool_use",
                db_path=self.db_path,
                allow_schema_migration=False,
            )

        self.assertEqual(0, exit_code)
        self.assertEqual("", stdout.getvalue())
        observations = list_externality_shadow_observations(self.db_path)
        self.assertEqual(0, len(observations))
        with sqlite3.connect(self.db_path) as conn:
            jobs = conn.execute(
                "SELECT status, envelope_json FROM externality_classification_jobs"
            ).fetchall()
        self.assertEqual(1, len(jobs))
        self.assertEqual("pending", jobs[0][0])
        self.assertNotIn("./opaque", jobs[0][1])

    def test_production_hook_does_not_recreate_missing_shadow_schema(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DROP TABLE externality_shadow_observations")
        payload = {
            "session_id": "session-no-ddl",
            "turn_id": "turn-no-ddl",
            "tool_use_id": "tool-no-ddl",
            "tool_name": "Bash",
            "cwd": str(self.workspace),
            "tool_input": {"command": "./opaque"},
        }
        stdin = type(
            "FakeStdin",
            (),
            {"buffer": __import__("io").BytesIO(json.dumps(payload).encode())},
        )()
        with patch("sys.stdin", stdin), patch.dict(
            os.environ,
            {
                "TOOLUSEPROXY_WORKSPACE_ROOT": str(self.workspace),
                "TOOLUSEPROXY_EXTERNALITY_JUDGE_PROVIDER": "off",
            },
            clear=False,
        ), patch("sys.stdout", new_callable=__import__("io").StringIO) as stdout:
            exit_code = run_hook(
                "pre_tool_use",
                db_path=self.db_path,
                allow_schema_migration=False,
            )

        self.assertEqual(0, exit_code)
        self.assertEqual("", stdout.getvalue())
        with sqlite3.connect(self.db_path) as conn:
            exists = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type = 'table' AND name = 'externality_shadow_observations'"
            ).fetchone()[0]
        self.assertEqual(0, exists)


if __name__ == "__main__":
    unittest.main()
