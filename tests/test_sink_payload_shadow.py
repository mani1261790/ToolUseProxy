from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from hook_monitor.analysis.sink_payload_evidence import (
    BashSinkPayloadEvidence,
    SinkPayloadSourceMatch,
)
from hook_monitor.runtime.sink_payload_shadow import (
    build_sink_payload_shadow_observation,
    build_sink_payload_shadow_report,
    list_sink_payload_shadow_observations,
    store_sink_payload_shadow_observations,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class SinkPayloadShadowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "events.db"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_builds_aggregate_observation_without_source_identity(self) -> None:
        observation = self._observation(self._evidence())

        self.assertEqual("1", observation.value_count_bucket)
        self.assertEqual("1-1024", observation.payload_bytes_bucket)
        self.assertEqual("resolved_payload_exact", observation.match_kind)
        self.assertEqual(1, observation.match_count)
        self.assertEqual("would_block", observation.shadow_action)
        self.assertNotIn("source-private", repr(observation))

    def test_static_literal_is_outside_file_payload_shadow_scope(self) -> None:
        evidence = replace(
            self._evidence(),
            extraction="static_values",
            snapshot_semantics="tool_input_literal",
        )

        observation = build_sink_payload_shadow_observation(
            evidence,
            pre_event_id="event-pre",
            analysis_run_id="analysis-run",
            session_id="session",
            tool_use_id="tool-use",
            baseline_action="allow",
        )

        self.assertIsNone(observation)

    def test_unsupported_resolution_is_recorded_as_unknown(self) -> None:
        evidence = replace(
            self._evidence(),
            resolution_status="unsupported",
            comparison_status="not_run",
            extraction="coarse_fallback",
            snapshot_semantics="unresolved",
            submitted_value_count=0,
            submitted_bytes=0,
            matches=(),
            resolution_reason="file_reference_missing",
        )

        observation = self._observation(evidence)

        self.assertEqual("none", observation.match_kind)
        self.assertEqual("unknown", observation.shadow_action)
        self.assertEqual("0", observation.payload_bytes_bucket)

    def test_first_observation_is_immutable_across_timing_replay(self) -> None:
        first = self._observation(self._evidence(duration=1.25))
        replay = replace(first, inspection_duration_ms=9.75)

        store_sink_payload_shadow_observations(self.db_path, (first,))
        store_sink_payload_shadow_observations(self.db_path, (replay,))

        stored = list_sink_payload_shadow_observations(self.db_path)
        self.assertEqual(1, len(stored))
        self.assertEqual(1.25, stored[0].inspection_duration_ms)

    def test_replay_with_different_policy_result_is_rejected(self) -> None:
        first = self._observation(self._evidence())
        conflicting = replace(
            first,
            baseline_action="block",
        )
        store_sink_payload_shadow_observations(self.db_path, (first,))

        with self.assertRaisesRegex(sqlite3.IntegrityError, "replay mismatch"):
            store_sink_payload_shadow_observations(
                self.db_path,
                (conflicting,),
            )

        self.assertEqual(
            "allow",
            list_sink_payload_shadow_observations(self.db_path)[0].baseline_action,
        )

    def test_schema_drift_is_detected_without_repair(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE sink_payload_shadow_observations (
                    observation_id TEXT PRIMARY KEY
                )
                """
            )

        with self.assertRaisesRegex(RuntimeError, "schema mismatch"):
            store_sink_payload_shadow_observations(
                self.db_path,
                (self._observation(self._evidence()),),
            )

        with sqlite3.connect(self.db_path) as conn:
            columns = conn.execute(
                "PRAGMA table_info(sink_payload_shadow_observations)"
            ).fetchall()
        self.assertEqual(["observation_id"], [row[1] for row in columns])

    def test_report_contains_aggregate_metrics_only(self) -> None:
        protected = self._observation(self._evidence(duration=4.0))
        public = replace(
            protected,
            observation_id="observation-public",
            pre_event_id="event-public",
            sink_node_id="sink-public",
            match_kind="none",
            match_count=0,
            inspection_duration_ms=10.0,
            shadow_action="would_allow",
        )

        report = build_sink_payload_shadow_report((protected, public))

        self.assertEqual(2, report["observation_count"])
        self.assertEqual(
            {"resolved_payload_exact": 1, "none": 1},
            report["match_kind"],
        )
        self.assertEqual(
            {"allow->would_allow": 1, "allow->would_block": 1},
            report["decision_diff"],
        )
        self.assertEqual(
            {"p50": 4.0, "p95": 10.0, "p99": 10.0, "max": 10.0},
            report["latency_ms"],
        )
        rendered = repr(report)
        self.assertNotIn("event-pre", rendered)
        self.assertNotIn("sink-http", rendered)
        self.assertNotIn("source-private", rendered)

    def test_report_cli_renders_value_free_json(self) -> None:
        store_sink_payload_shadow_observations(
            self.db_path,
            (self._observation(self._evidence()),),
        )

        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "report_sink_payload_shadow.py"),
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
        self.assertEqual(
            {"allow->would_block": 1},
            report["decision_diff"],
        )
        self.assertNotIn("event-pre", result.stdout)
        self.assertNotIn("sink-http", result.stdout)
        self.assertNotIn("source-private", result.stdout)

    @staticmethod
    def _evidence(*, duration: float = 1.25) -> BashSinkPayloadEvidence:
        return BashSinkPayloadEvidence(
            workspace_id="workspace",
            sink_node_id="sink-http",
            segment_index=0,
            resolution_status="evaluated",
            comparison_status="evaluated",
            extraction="resolved_file",
            snapshot_semantics="pre_execution_file_snapshot",
            resolver_version="resolver-v1",
            evidence_version="evidence-v1",
            submitted_value_count=1,
            submitted_bytes=48,
            matches=(
                SinkPayloadSourceMatch(
                    source_node_kind="source_chunk",
                    source_node_id="source-private",
                    evidence_level="content_exact",
                    method="resolved_payload_exact",
                    score=1.0,
                ),
            ),
            resolution_reason=None,
            comparison_reason=None,
            inspection_duration_ms=duration,
        )

    @staticmethod
    def _observation(
        evidence: BashSinkPayloadEvidence,
    ):
        observation = build_sink_payload_shadow_observation(
            evidence,
            pre_event_id="event-pre",
            analysis_run_id="analysis-run",
            session_id="session",
            tool_use_id="tool-use",
            baseline_action="allow",
        )
        assert observation is not None
        return observation


if __name__ == "__main__":
    unittest.main()
