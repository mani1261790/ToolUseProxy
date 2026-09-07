from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION, EventStore
from tooluseproxy.migration_backups import (
    mark_migration_backups_verified,
    record_migration_backup,
)
from tooluseproxy.cli import main as tooluseproxy_main
from tooluseproxy import storage_cleanup
from tooluseproxy.storage_cleanup import (
    STORAGE_ACTION_BYTES,
    STORAGE_RETENTION_DAYS,
    STORAGE_WARNING_BYTES,
    StorageCleanupPlanError,
    apply_storage_cleanup,
    plan_storage_cleanup,
    validate_storage_cleanup_review,
)


class StorageCleanupPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary.name) / "plugin-data"
        self.data_dir.mkdir(mode=0o700)
        self.db_path = self.data_dir / "events.db"
        EventStore(self.db_path).initialize()
        self._seed_database()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.backup = self.data_dir / "events.db.pre-migration-v7.bak"
        self.backup.write_bytes(b"x" * 123)
        self.source = Path(self.temporary.name) / "private-source.txt"
        self.source.write_text("SYNTHETIC_PRIVATE_VALUE", encoding="utf-8")
        self.now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_database(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO workspaces (
                    workspace_id, canonical_root, lexical_root, discovered_by
                ) VALUES (
                    'ws-old', '/synthetic/ws-old', '/synthetic/ws-old', 'test'
                )
                """
            )
            events = (
                (
                    "old-pre", "pre_tool_use", "old-complete", "ws-old",
                    '{"private":"SYNTHETIC_OLD_VALUE"}', "2026-07-01 00:00:00",
                ),
                (
                    "old-stop", "stop", "old-complete", "ws-old",
                    "{}", "2026-07-01 00:01:00",
                ),
                (
                    "old-incomplete", "pre_tool_use", "old-incomplete", "ws-old",
                    "{}", "2026-07-02 00:00:00",
                ),
                (
                    "mixed-old", "pre_tool_use", "mixed", "ws-old",
                    "{}", "2026-07-01 00:00:00",
                ),
                (
                    "mixed-new", "stop", "mixed", "ws-old",
                    "{}", "2026-09-01 00:00:00",
                ),
                (
                    "unscoped-old", "pre_tool_use", None, None,
                    "{}", "2026-07-03 00:00:00",
                ),
                (
                    "recent", "stop", "recent", "ws-old",
                    "{}", "2026-09-02 00:00:00",
                ),
            )
            conn.executemany(
                """
                INSERT INTO events (
                    event_id, phase, session_id, workspace_id,
                    payload_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                events,
            )
            conn.executemany(
                """
                INSERT INTO artifact_contents (
                    text_hash, text, normalized_text, token_count
                ) VALUES (?, ?, ?, 1)
                """,
                (
                    ("a" * 64, "SYNTHETIC_OLD_VALUE", "synthetic_old_value"),
                    ("b" * 64, "PUBLIC_RECENT_VALUE", "public_recent_value"),
                    ("c" * 64, "SYNTHETIC_OLD_VALUE", "synthetic_old_value"),
                ),
            )
            conn.executemany(
                """
                INSERT INTO artifacts (
                    artifact_id, event_id, role, text_hash, recorded_at
                ) VALUES (?, ?, 'tool_input', ?, ?)
                """,
                (
                    (
                        "artifact-old", "old-pre", "a" * 64,
                        "2026-07-01 00:00:00",
                    ),
                    (
                        "artifact-new", "recent", "b" * 64,
                        "2026-09-02 00:00:00",
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO artifact_fragments (
                    fragment_id, artifact_id, json_pointer, semantic_role,
                    text_hash, recorded_at
                ) VALUES (
                    'fragment-old', 'artifact-old', '/private', 'value',
                    ?, '2026-07-01 00:00:00'
                )
                """,
                ("c" * 64,),
            )
            conn.execute(
                """
                INSERT INTO content_similarity_features (
                    profile_version, text_hash, feature
                ) VALUES ('test-profile', ?, 'abcdef')
                """,
                ("c" * 64,),
            )
            conn.execute(
                """
                INSERT INTO fragment_exact_index (
                    workspace_id, session_id, fragment_id, sequence_no, text_hash
                ) VALUES ('ws-old', 'old-complete', 'fragment-old', 1, ?)
                """,
                ("c" * 64,),
            )
            conn.execute(
                """
                INSERT INTO tool_operations (
                    operation_id, event_id, artifact_id, parent_fragment_id,
                    session_id, adapter, operation_index, operation_kind,
                    recorded_at
                ) VALUES (
                    'operation-old', 'old-pre', 'artifact-old', 'fragment-old',
                    'old-complete', 'test', 0, 'read', '2026-07-01 00:00:10'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO tool_operation_outcomes (
                    post_event_id, operation_id, session_id, outcome, recorded_at
                ) VALUES (
                    'old-stop', 'operation-old', 'old-complete', 'succeeded',
                    '2026-07-01 00:01:10'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO resource_snapshots (
                    snapshot_id, post_event_id, operation_id, session_id,
                    path_role, requested_path, resource_state, capture_status,
                    file_kind, captured_bytes, duration_ms, recorded_at
                ) VALUES (
                    'snapshot-old', 'old-stop', 'operation-old', 'old-complete',
                    'source', 'synthetic.txt', 'present', 'captured', 'file',
                    0, 1.0, '2026-07-01 00:01:10'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id, detector_version, config_json,
                    started_at, completed_at, workspace_id, session_id
                ) VALUES (
                    'run-old', 'test', '{}', '2026-07-01 00:01:20',
                    '2026-07-01 00:01:21', 'ws-old', 'old-complete'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_run_graphs (
                    analysis_run_id, workspace_id, coverage, recorded_at,
                    node_snapshot_version
                ) VALUES (
                    'run-old', 'ws-old', 'session', '2026-07-01 00:01:21',
                    'test'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_node_snapshots (
                    workspace_id, snapshot_hash, node_kind, node_id,
                    metadata_json, recorded_at
                ) VALUES (
                    'ws-old', 'snapshot-hash-old', 'artifact_fragment',
                    'fragment-old', '{}', '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_run_nodes (
                    analysis_run_id, workspace_id, node_kind, node_id,
                    snapshot_hash
                ) VALUES (
                    'run-old', 'ws-old', 'artifact_fragment', 'fragment-old',
                    'snapshot-hash-old'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_run_flow_edges (
                    analysis_run_id, edge_id, src_node_kind, src_node_id,
                    dst_node_kind, dst_node_id, relation, evidence_level,
                    method, score, reason, recorded_at
                ) VALUES (
                    'run-old', 'run-edge-old', 'artifact_fragment',
                    'fragment-old', 'sink', 'sink-old', 'flows_to', 'exact',
                    'test', 1.0, 'test', '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO policy_decisions (
                    decision_id, finding_id, analysis_run_id, action, severity,
                    sink_type, source_node_kind, source_node_id, sink_node_id,
                    path_score, reason, user_message, technical_summary,
                    trace_command, path_summary_json, created_at
                ) VALUES (
                    'decision-old', 'finding-old', 'run-old', 'block', 'critical',
                    'network', 'artifact_fragment', 'fragment-old', 'sink-old',
                    1.0, 'test', 'test', 'test', 'test', '[]',
                    '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO resource_versions (
                    workspace_id, node_id, path, sequence_no, session_id,
                    resource_state, recorded_at
                ) VALUES (
                    'ws-old', 'resource-old', 'synthetic.txt', 1,
                    'old-complete', 'present', '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO sink_candidates (
                    workspace_id, node_id, sink_type, label, session_id,
                    sequence_no, metadata_json, recorded_at
                ) VALUES (
                    'ws-old', 'sink-old', 'network', 'synthetic',
                    'old-complete', 1, '{}', '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO analysis_cursors (
                    workspace_id, session_id, detector_version, source_digest,
                    last_sequence_no, status, updated_at
                ) VALUES (
                    'ws-old', 'old-complete', 'test', 'digest', 1, 'ready',
                    '2026-07-01 00:01:21'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO pilot_issue_bindings (problem_key, repository, issue_number)
                VALUES ('problem', 'owner/repository', 1)
                """
            )

    def test_plan_classifies_storage_and_whole_expired_sessions_without_writes(
        self,
    ) -> None:
        database_before = self.db_path.read_bytes()
        backup_before = self.backup.read_bytes()
        source_before = self.source.read_bytes()

        plan = plan_storage_cleanup(self.db_path, now=self.now)
        payload = plan.to_payload()

        self.assertEqual(STORAGE_RETENTION_DAYS, payload["retention_days"])
        self.assertEqual("2026-08-08T12:00:00Z", payload["cutoff_at"])
        self.assertEqual(2, payload["retention_candidates"]["eligible_session_count"])
        self.assertEqual(
            1,
            payload["retention_candidates"]["eligible_incomplete_session_count"],
        )
        self.assertEqual(
            1,
            payload["retention_candidates"]["eligible_unscoped_event_count"],
        )
        rows = payload["retention_candidates"]["rows"]
        self.assertEqual(4, rows["events"])
        self.assertEqual(1, rows["analysis_runs"])
        self.assertEqual(1, rows["analysis_run_nodes"])
        self.assertEqual(1, rows["policy_decisions"])
        self.assertEqual(1, rows["resource_snapshots"])
        self.assertEqual(1, rows["artifacts"])
        self.assertEqual(1, rows["artifact_fragments"])
        self.assertEqual(1, rows["fragment_exact_index"])
        self.assertGreater(
            payload["storage"]["categories"]["improvement_feedback"][
                "allocated_bytes"
            ],
            0,
        )
        self.assertTrue(payload["storage"]["category_byte_measurement_available"])
        self.assertTrue(payload["preserved"]["improvement_feedback"])
        self.assertTrue(payload["preserved"]["protected_source_registrations"])
        self.assertEqual(1, payload["storage"]["migration_backup_count"])
        self.assertEqual(123, payload["storage"]["migration_backup_bytes"])
        self.assertTrue(payload["migration_backups"]["cleanup_blocked"])
        self.assertEqual(
            1,
            payload["migration_backups"]["awaiting_verification_count"],
        )
        self.assertEqual(0, payload["migration_backups"]["eligible_count"])
        self.assertEqual(0, payload["database_changes"])
        self.assertEqual(0, payload["source_file_changes"])
        self.assertFalse(payload["protected_manifest_read"])
        self.assertFalse(payload["network_used"])
        self.assertEqual("2026-09-07T12:00:00Z", payload["reviewed_at"])
        self.assertRegex(payload["plan_revision"], r"^sc4_[0-9a-f]{64}$")
        self.assertEqual(database_before, self.db_path.read_bytes())
        self.assertEqual(backup_before, self.backup.read_bytes())
        self.assertEqual(source_before, self.source.read_bytes())
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(str(self.temporary.name), rendered)
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", rendered)
        self.assertNotIn("SYNTHETIC_OLD_VALUE", rendered)

    def test_revision_binds_database_state_but_not_free_disk_measurement(self) -> None:
        first = plan_storage_cleanup(self.db_path, now=self.now)
        repeated = plan_storage_cleanup(self.db_path, now=self.now)
        self.assertEqual(first.plan_revision, repeated.plan_revision)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO events (event_id, phase, payload_json, recorded_at)
                VALUES ('later', 'stop', '{}', '2026-09-07 12:00:01')
                """
            )
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        changed = plan_storage_cleanup(self.db_path, now=self.now)
        self.assertNotEqual(first.plan_revision, changed.plan_revision)

    def test_revision_binds_wal_byte_inventory(self) -> None:
        with patch.object(storage_cleanup, "_regular_file_size", return_value=0):
            without_wal = plan_storage_cleanup(self.db_path, now=self.now)
        with patch.object(storage_cleanup, "_regular_file_size", return_value=4096):
            with_wal = plan_storage_cleanup(self.db_path, now=self.now)

        self.assertNotEqual(without_wal.plan_revision, with_wal.plan_revision)
        self.assertEqual(4096, with_wal.database_wal_bytes)

    def test_review_window_starts_after_a_slow_plan_finishes(self) -> None:
        validate_storage_cleanup_review(
            cutoff_at="2026-08-08T12:00:00Z",
            reviewed_at="2026-09-07T12:14:00Z",
            now=datetime(2026, 9, 7, 12, 18, 59, tzinfo=UTC),
        )

        with self.assertRaises(StorageCleanupPlanError) as expired:
            validate_storage_cleanup_review(
                cutoff_at="2026-08-08T12:00:00Z",
                reviewed_at="2026-09-07T12:14:00Z",
                now=datetime(2026, 9, 7, 12, 19, 1, tzinfo=UTC),
            )
        self.assertEqual("storage_plan_expired", expired.exception.code)

        with self.assertRaises(StorageCleanupPlanError) as before_start:
            validate_storage_cleanup_review(
                cutoff_at="2026-08-08T12:00:00Z",
                reviewed_at="2026-09-07T11:59:59Z",
                now=datetime(2026, 9, 7, 12, 0, tzinfo=UTC),
            )
        self.assertEqual(
            "storage_plan_review_time_invalid",
            before_start.exception.code,
        )

    def test_plan_keeps_retention_candidates_when_page_measurement_is_unavailable(
        self,
    ) -> None:
        with patch.object(storage_cleanup, "_owned_page_bytes", return_value=None):
            payload = plan_storage_cleanup(self.db_path, now=self.now).to_payload()

        self.assertEqual(2, payload["retention_candidates"]["eligible_session_count"])
        self.assertEqual(4, payload["retention_candidates"]["rows"]["events"])
        self.assertFalse(payload["storage"]["category_byte_measurement_available"])
        self.assertIsNone(
            payload["storage"]["categories"]["detailed_operation_records"][
                "allocated_bytes"
            ]
        )
        self.assertIsNone(
            payload["retention_candidates"]["estimated_reclaimable_bytes"]
        )
        self.assertEqual(
            "unavailable", payload["retention_candidates"]["estimate_method"]
        )

    def test_page_measurement_returns_unknown_when_dbstat_is_unavailable(self) -> None:
        connection = MagicMock()
        connection.execute.side_effect = [
            [("events", "events")],
            sqlite3.OperationalError("no such table: dbstat"),
        ]

        self.assertIsNone(storage_cleanup._owned_page_bytes(connection))

    def test_cli_plan_is_value_free_and_uses_fixed_thresholds(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = tooluseproxy_main(
                [
                    "storage",
                    "cleanup",
                    "plan",
                    "--data-dir",
                    str(self.data_dir),
                    "--json",
                ]
            )
        self.assertEqual(0, exit_code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(STORAGE_WARNING_BYTES, payload["thresholds"]["warning_bytes"])
        self.assertEqual(STORAGE_ACTION_BYTES, payload["thresholds"]["action_bytes"])
        self.assertFalse(payload["thresholds"]["recent_records_deleted_for_capacity"])
        self.assertNotIn(str(self.data_dir), stdout.getvalue())
        self.assertNotIn("SYNTHETIC_OLD_VALUE", stdout.getvalue())

    def test_symlink_database_is_rejected_without_following_it(self) -> None:
        link = self.data_dir / "linked.db"
        link.symlink_to(self.db_path)
        with self.assertRaises(StorageCleanupPlanError) as caught:
            plan_storage_cleanup(link, now=self.now)
        self.assertEqual("storage_database_symlink", caught.exception.code)

    def test_apply_deletes_one_bounded_batch_and_resumes_with_next_revision(
        self,
    ) -> None:
        first = plan_storage_cleanup(self.db_path, now=self.now)
        result = apply_storage_cleanup(
            self.db_path,
            cutoff_at=first.cutoff_at,
            expected_plan_revision=first.plan_revision,
            batch_size=1,
        )

        self.assertEqual(1, result.deleted_session_count)
        self.assertEqual(0, result.deleted_incomplete_session_count)
        self.assertEqual(0, result.deleted_unscoped_event_count)
        self.assertEqual(1, result.remaining_session_count)
        self.assertEqual(1, result.remaining_unscoped_event_count)
        with sqlite3.connect(self.db_path) as conn:
            remaining = {
                row[0] for row in conn.execute("SELECT event_id FROM events")
            }
            self.assertNotIn("old-pre", remaining)
            self.assertNotIn("old-stop", remaining)
            self.assertIn("old-incomplete", remaining)
            self.assertIn("unscoped-old", remaining)
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM pilot_issue_bindings"
                ).fetchone()[0],
            )
            self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])
            for table in (
                "analysis_runs",
                "analysis_run_graphs",
                "analysis_run_nodes",
                "analysis_run_flow_edges",
                "analysis_node_snapshots",
                "policy_decisions",
                "resource_snapshots",
                "tool_operations",
                "tool_operation_outcomes",
                "resource_versions",
                "sink_candidates",
                "analysis_cursors",
            ):
                self.assertEqual(
                    0,
                    conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0],
                    table,
                )
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0])

        resumed = apply_storage_cleanup(
            self.db_path,
            cutoff_at=first.cutoff_at,
            expected_plan_revision=result.next_plan_revision,
            batch_size=2,
        )
        self.assertEqual(1, resumed.deleted_session_count)
        self.assertEqual(1, resumed.deleted_incomplete_session_count)
        self.assertEqual(1, resumed.deleted_unscoped_event_count)
        self.assertEqual(0, resumed.remaining_session_count)
        self.assertEqual(0, resumed.remaining_unscoped_event_count)
        with sqlite3.connect(self.db_path) as conn:
            remaining = {
                row[0] for row in conn.execute("SELECT event_id FROM events")
            }
            self.assertEqual({"mixed-old", "mixed-new", "recent"}, remaining)
            self.assertEqual(
                [("PUBLIC_RECENT_VALUE",)],
                conn.execute("SELECT text FROM artifact_contents").fetchall(),
            )

    def test_apply_deletes_only_mature_verified_backup_and_keeps_runtime_db(
        self,
    ) -> None:
        self.backup.unlink()
        backup = self.data_dir / (
            f"events.db.pre-migration-v{CURRENT_SCHEMA_VERSION - 1}.bak"
        )
        with sqlite3.connect(backup) as conn:
            conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION - 1}")
            conn.execute("CREATE TABLE old_runtime (id INTEGER PRIMARY KEY)")
        created_at = self.now - timedelta(days=9)
        record_migration_backup(
            backup,
            source_schema_version=CURRENT_SCHEMA_VERSION - 1,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=created_at,
        )
        mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.now - timedelta(days=8),
        )

        plan = plan_storage_cleanup(self.db_path, now=self.now)
        payload = plan.to_payload()
        self.assertEqual(1, payload["migration_backups"]["eligible_count"])
        self.assertGreater(payload["migration_backups"]["eligible_bytes"], 0)

        result = apply_storage_cleanup(
            self.db_path,
            cutoff_at=plan.cutoff_at,
            expected_plan_revision=plan.plan_revision,
            batch_size=1,
        )

        self.assertEqual("applied", result.migration_backup_cleanup_status)
        self.assertEqual(1, result.deleted_migration_backup_count)
        self.assertFalse(backup.exists())
        EventStore(self.db_path).require_runtime_schema()
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])

    def test_pending_and_recent_dependent_work_skip_old_sessions(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id, detector_version, config_json, started_at,
                    completed_at, workspace_id, session_id
                ) VALUES (
                    'run-pending', 'test', '{}', '2026-07-02 00:00:01',
                    NULL, 'ws-old', 'old-incomplete'
                )
                """
            )
        pending = plan_storage_cleanup(self.db_path, now=self.now)
        self.assertEqual(1, pending.eligible_session_count)
        self.assertEqual(1, pending.pending_session_count)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM analysis_runs WHERE analysis_run_id = 'run-pending'")
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id, detector_version, config_json, started_at,
                    completed_at, workspace_id, session_id
                ) VALUES (
                    'run-recent', 'test', '{}', '2026-09-01 00:00:00',
                    '2026-09-01 00:00:01', 'ws-old', 'old-incomplete'
                )
                """
            )
        recent = plan_storage_cleanup(self.db_path, now=self.now)
        self.assertEqual(1, recent.eligible_session_count)
        self.assertEqual(0, recent.pending_session_count)

    def test_unscoped_event_with_pending_redaction_work_is_preserved(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO redaction_plans (
                    plan_id, analysis_run_id, pre_event_id, workspace_id,
                    session_id, tool_use_id, tool_name, adapter, profile_id,
                    profile_version, profile_registry_version, mode, status,
                    planner_version, structure_sha256_before,
                    critical_finding_count, replacement_count, created_at
                ) VALUES (
                    'pending-unscoped-plan', 'run-old', 'unscoped-old',
                    'ws-old', 'old-complete', 'tool-use', 'Bash', 'bash',
                    'profile', '1', '1', 'preview', 'eligible', 'test',
                    ?, 1, 0, '2026-07-03 00:00:01'
                )
                """,
                ("d" * 64,),
            )

        plan = plan_storage_cleanup(self.db_path, now=self.now)

        self.assertEqual(1, plan.eligible_session_count)
        self.assertEqual(1, plan.pending_session_count)
        self.assertEqual(0, plan.eligible_unscoped_event_count)

    def test_shared_content_and_recent_detection_survive_old_session_cleanup(
        self,
    ) -> None:
        shared_hash = "c" * 64
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO artifact_fragments (
                    fragment_id, artifact_id, json_pointer, semantic_role,
                    text_hash, recorded_at
                ) VALUES (
                    'fragment-recent-shared', 'artifact-new', '/shared', 'value',
                    ?, '2026-09-02 00:00:01'
                )
                """,
                (shared_hash,),
            )
            conn.execute(
                """
                INSERT INTO fragment_exact_index (
                    workspace_id, session_id, fragment_id, sequence_no, text_hash
                ) VALUES (
                    'ws-old', 'recent', 'fragment-recent-shared', 1, ?
                )
                """,
                (shared_hash,),
            )

        plan = plan_storage_cleanup(self.db_path, now=self.now)
        result = apply_storage_cleanup(
            self.db_path,
            cutoff_at=plan.cutoff_at,
            expected_plan_revision=plan.plan_revision,
            batch_size=1,
        )

        self.assertEqual(1, result.deleted_session_count)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM artifact_contents WHERE text_hash = ?",
                    (shared_hash,),
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM content_similarity_features "
                    "WHERE text_hash = ?",
                    (shared_hash,),
                ).fetchone()[0],
            )
        EventStore(self.db_path).require_runtime_schema()
        self.assertEqual(
            ["fragment-recent-shared"],
            EventStore(self.db_path).find_similarity_candidate_fragment_ids(
                "recent",
                shared_hash,
                set(),
                2,
                limit=10,
                workspace_id="ws-old",
                query_normalized_length=len("synthetic_old_value"),
                minimum_length=1,
            ),
        )

    def test_recent_cross_session_reference_preserves_the_old_source_session(
        self,
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO fragment_exact_index (
                    workspace_id, session_id, fragment_id, sequence_no, text_hash
                ) VALUES (
                    'ws-old', 'recent', 'fragment-old', 2, ?
                )
                """,
                ("c" * 64,),
            )

        plan = plan_storage_cleanup(self.db_path, now=self.now)

        self.assertEqual(1, plan.eligible_session_count)
        self.assertEqual(1, plan.eligible_incomplete_session_count)
        self.assertEqual(1, plan.eligible_unscoped_event_count)
        self.assertEqual(2, plan.candidate_rows["events"])

    def test_cutoff_is_strict_and_invalid_timestamps_are_preserved(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO events (
                    event_id, phase, session_id, workspace_id,
                    payload_json, recorded_at
                ) VALUES (?, 'stop', ?, 'ws-old', '{}', ?)
                """,
                (
                    ("before-cutoff", "before-cutoff", "2026-08-08 11:59:59"),
                    ("at-cutoff", "at-cutoff", "2026-08-08 12:00:00"),
                    ("invalid-time", "invalid-time", "not-a-time"),
                ),
            )
        plan = plan_storage_cleanup(self.db_path, now=self.now)
        self.assertEqual(3, plan.eligible_session_count)
        self.assertEqual(5, plan.candidate_rows["events"])

    def test_plan_change_before_write_rejects_without_partial_cleanup(self) -> None:
        plan = plan_storage_cleanup(self.db_path, now=self.now)
        original_write_connection = storage_cleanup._write_connection

        def mutate_before_lock(path: Path) -> sqlite3.Connection:
            with sqlite3.connect(path) as conn:
                conn.execute(
                    """
                    INSERT INTO events (event_id, phase, payload_json, recorded_at)
                    VALUES ('concurrent', 'stop', '{}', '2026-09-07 12:00:01')
                    """
                )
            return original_write_connection(path)

        with patch.object(
            storage_cleanup,
            "_write_connection",
            side_effect=mutate_before_lock,
        ):
            with self.assertRaises(StorageCleanupPlanError) as caught:
                apply_storage_cleanup(
                    self.db_path,
                    cutoff_at=plan.cutoff_at,
                    expected_plan_revision=plan.plan_revision,
                )
        self.assertEqual("storage_plan_changed", caught.exception.code)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM events WHERE event_id = 'old-pre'"
                ).fetchone()[0],
            )

    def test_unexpected_failure_rolls_back_the_whole_batch(self) -> None:
        plan = plan_storage_cleanup(self.db_path, now=self.now)

        def fail_after_write(conn: sqlite3.Connection) -> dict[str, int]:
            conn.execute(
                "DELETE FROM analysis_cursors WHERE session_id = 'old-complete'"
            )
            raise RuntimeError("injected cleanup failure")

        with patch.object(
            storage_cleanup,
            "_delete_cleanup_targets",
            side_effect=fail_after_write,
        ):
            with self.assertRaisesRegex(RuntimeError, "injected cleanup failure"):
                apply_storage_cleanup(
                    self.db_path,
                    cutoff_at=plan.cutoff_at,
                    expected_plan_revision=plan.plan_revision,
                )
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM analysis_cursors "
                    "WHERE session_id = 'old-complete'"
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                conn.execute(
                    "SELECT COUNT(*) FROM events WHERE event_id = 'old-pre'"
                ).fetchone()[0],
            )

    def test_cli_apply_is_value_free_and_requires_the_exact_plan(self) -> None:
        plan = plan_storage_cleanup(self.db_path)
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = tooluseproxy_main(
                [
                    "storage",
                    "cleanup",
                    "apply",
                    "--cutoff-at",
                    plan.cutoff_at,
                    "--reviewed-at",
                    plan.reviewed_at,
                    "--plan-revision",
                    plan.plan_revision,
                    "--batch-size",
                    "1",
                    "--data-dir",
                    str(self.data_dir),
                    "--json",
                ]
            )
        self.assertEqual(0, exit_code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(1, payload["deleted"]["session_count"])
        self.assertEqual(0, payload["source_file_changes"])
        self.assertFalse(payload["protected_manifest_read"])
        self.assertNotIn(str(self.data_dir), stdout.getvalue())
        self.assertNotIn("SYNTHETIC_OLD_VALUE", stdout.getvalue())

        with redirect_stdout(StringIO()):
            stale_exit = tooluseproxy_main(
                [
                    "storage",
                    "cleanup",
                    "apply",
                    "--cutoff-at",
                    plan.cutoff_at,
                    "--reviewed-at",
                    plan.reviewed_at,
                    "--plan-revision",
                    plan.plan_revision,
                    "--data-dir",
                    str(self.data_dir),
                    "--json",
                ]
            )
        self.assertEqual(1, stale_exit)
if __name__ == "__main__":
    unittest.main()
