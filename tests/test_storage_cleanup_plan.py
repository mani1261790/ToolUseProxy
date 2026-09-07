from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from hook_monitor.runtime.storage import EventStore
from tooluseproxy.cli import main as tooluseproxy_main
from tooluseproxy import storage_cleanup
from tooluseproxy.storage_cleanup import (
    STORAGE_ACTION_BYTES,
    STORAGE_RETENTION_DAYS,
    STORAGE_WARNING_BYTES,
    StorageCleanupPlanError,
    plan_storage_cleanup,
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
                INSERT INTO artifacts (
                    artifact_id, event_id, role, text, text_hash,
                    normalized_text, token_count, recorded_at
                ) VALUES (?, ?, 'tool_input', ?, ?, ?, 1, ?)
                """,
                (
                    (
                        "artifact-old", "old-pre", "SYNTHETIC_OLD_VALUE",
                        "a" * 64, "synthetic_old_value", "2026-07-01 00:00:00",
                    ),
                    (
                        "artifact-new", "recent", "PUBLIC_RECENT_VALUE",
                        "b" * 64, "public_recent_value", "2026-09-02 00:00:00",
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO artifact_fragments (
                    fragment_id, artifact_id, json_pointer, semantic_role,
                    text, text_hash, normalized_text, token_count, recorded_at
                ) VALUES (
                    'fragment-old', 'artifact-old', '/private', 'value',
                    'SYNTHETIC_OLD_VALUE', ?, 'synthetic_old_value', 1,
                    '2026-07-01 00:00:00'
                )
                """,
                ("c" * 64,),
            )
            conn.execute(
                """
                INSERT INTO fragment_shingles (
                    workspace_id, session_id, fragment_id, sequence_no, shingle
                ) VALUES ('ws-old', 'old-complete', 'fragment-old', 1, 'abcdef')
                """
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
        self.assertEqual(1, rows["artifacts"])
        self.assertEqual(1, rows["artifact_fragments"])
        self.assertEqual(1, rows["fragment_shingles"])
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
        self.assertEqual(0, payload["database_changes"])
        self.assertEqual(0, payload["source_file_changes"])
        self.assertFalse(payload["protected_manifest_read"])
        self.assertFalse(payload["network_used"])
        self.assertRegex(payload["plan_revision"], r"^sc1_[0-9a-f]{64}$")
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


if __name__ == "__main__":
    unittest.main()
