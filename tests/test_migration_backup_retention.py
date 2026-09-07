from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from hook_monitor.runtime.storage import CURRENT_SCHEMA_VERSION, EventStore
from tooluseproxy import migration_backups
from tooluseproxy.migration_backups import (
    MIGRATION_BACKUP_LOCK_FILENAME,
    MIGRATION_BACKUP_STATE_FILENAME,
    MigrationBackupError,
    delete_verified_migration_backups,
    inventory_migration_backups,
    mark_migration_backups_verified,
    record_migration_backup,
)


class MigrationBackupRetentionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary.name)
        self.db_path = self.data_dir / "events.db"
        EventStore(self.db_path).initialize()
        self.created_at = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
        self.verified_at = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create_backup(self, version: int, suffix: str = "") -> Path:
        backup = self.data_dir / f"events.db.pre-migration-v{version}.bak{suffix}"
        with sqlite3.connect(backup) as conn:
            conn.execute(f"PRAGMA user_version = {version}")
            conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY)")
        timestamp = self.created_at.timestamp()
        os.utime(backup, (timestamp, timestamp))
        return backup

    def _record_and_verify(self, backup: Path, version: int) -> None:
        record_migration_backup(
            backup,
            source_schema_version=version,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at,
        )
        self.assertEqual(
            1,
            mark_migration_backups_verified(
                self.db_path,
                runtime_version="test-runtime",
                now=self.verified_at,
            ),
        )

    def test_verified_backup_becomes_eligible_only_after_seven_days(self) -> None:
        backup = self._create_backup(CURRENT_SCHEMA_VERSION - 1)
        self._record_and_verify(backup, CURRENT_SCHEMA_VERSION - 1)

        before = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=7, seconds=-1),
        )
        at_boundary = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=7),
        )

        self.assertEqual(0, before.eligible_count)
        self.assertEqual(1, before.recent_count)
        self.assertEqual(1, at_boundary.eligible_count)
        self.assertFalse(at_boundary.cleanup_blocked)

    def test_repeated_verification_does_not_restart_the_waiting_period(self) -> None:
        backup = self._create_backup(CURRENT_SCHEMA_VERSION - 1)
        self._record_and_verify(backup, CURRENT_SCHEMA_VERSION - 1)
        mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.verified_at + timedelta(days=6),
        )

        inventory = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=7),
        )

        self.assertEqual(1, inventory.eligible_count)

    def test_unverified_new_backup_blocks_deletion_of_older_verified_backup(self) -> None:
        old_backup = self._create_backup(CURRENT_SCHEMA_VERSION - 2)
        self._record_and_verify(old_backup, CURRENT_SCHEMA_VERSION - 2)
        self._create_backup(CURRENT_SCHEMA_VERSION - 1, ".1")

        inventory = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=8),
        )

        self.assertTrue(inventory.cleanup_blocked)
        self.assertEqual(1, inventory.awaiting_verification_count)
        self.assertEqual(0, inventory.eligible_count)
        self.assertTrue(old_backup.exists())

    def test_legacy_backup_is_adopted_only_by_current_runtime_verification(self) -> None:
        backup = self._create_backup(CURRENT_SCHEMA_VERSION - 1)
        before = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=8),
        )
        self.assertTrue(before.cleanup_blocked)
        self.assertEqual(1, before.awaiting_verification_count)

        verified = mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.verified_at,
        )
        after = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=7),
        )

        self.assertEqual(1, verified)
        self.assertEqual(1, after.eligible_count)
        state = json.loads(
            (self.data_dir / MIGRATION_BACKUP_STATE_FILENAME).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            "adopted_legacy_backup",
            state["backups"][backup.name]["provenance"],
        )

    def test_changed_backup_identity_blocks_all_deletion(self) -> None:
        backup = self._create_backup(CURRENT_SCHEMA_VERSION - 1)
        self._record_and_verify(backup, CURRENT_SCHEMA_VERSION - 1)
        with backup.open("ab") as output:
            output.write(b"changed")

        inventory = inventory_migration_backups(
            self.db_path,
            now=self.verified_at + timedelta(days=8),
        )

        self.assertTrue(inventory.cleanup_blocked)
        self.assertEqual(1, inventory.identity_mismatch_count)
        self.assertEqual(0, inventory.eligible_count)

    def test_delete_requires_exact_inventory_and_updates_private_state(self) -> None:
        first = self._create_backup(CURRENT_SCHEMA_VERSION - 2)
        second = self._create_backup(CURRENT_SCHEMA_VERSION - 1, ".1")
        record_migration_backup(
            first,
            source_schema_version=CURRENT_SCHEMA_VERSION - 2,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at,
        )
        record_migration_backup(
            second,
            source_schema_version=CURRENT_SCHEMA_VERSION - 1,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at + timedelta(hours=1),
        )
        mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.verified_at,
        )
        cleanup_time = self.verified_at + timedelta(days=8)
        inventory = inventory_migration_backups(self.db_path, now=cleanup_time)

        with self.assertRaises(MigrationBackupError) as caught:
            delete_verified_migration_backups(
                self.db_path,
                now=cleanup_time,
                expected_inventory_digest="0" * 64,
                limit=1,
            )
        self.assertEqual("migration_backup_inventory_changed", caught.exception.code)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

        deletion = delete_verified_migration_backups(
            self.db_path,
            now=cleanup_time,
            expected_inventory_digest=inventory.inventory_digest,
            limit=1,
        )
        self.assertEqual(1, deletion.deleted_count)
        self.assertGreater(deletion.deleted_bytes, 0)
        self.assertTrue(deletion.completed)
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertEqual(
            0,
            os.stat(self.data_dir / MIGRATION_BACKUP_STATE_FILENAME).st_mode
            & 0o077,
        )
        self.assertTrue((self.data_dir / MIGRATION_BACKUP_LOCK_FILENAME).exists())

    def test_failed_current_database_integrity_check_blocks_deletion(self) -> None:
        backup = self._create_backup(CURRENT_SCHEMA_VERSION - 1)
        self._record_and_verify(backup, CURRENT_SCHEMA_VERSION - 1)

        with patch.object(
            migration_backups,
            "_database_integrity_ok",
            return_value=False,
        ):
            inventory = inventory_migration_backups(
                self.db_path,
                now=self.verified_at + timedelta(days=8),
            )

        self.assertFalse(inventory.current_database_integrity_ok)
        self.assertTrue(inventory.cleanup_blocked)
        self.assertEqual(0, inventory.eligible_count)
        self.assertTrue(backup.exists())

    def test_interrupted_batch_records_progress_and_resumes_safely(self) -> None:
        first = self._create_backup(CURRENT_SCHEMA_VERSION - 2)
        second = self._create_backup(CURRENT_SCHEMA_VERSION - 1, ".1")
        record_migration_backup(
            first,
            source_schema_version=CURRENT_SCHEMA_VERSION - 2,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at,
        )
        record_migration_backup(
            second,
            source_schema_version=CURRENT_SCHEMA_VERSION - 1,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at + timedelta(hours=1),
        )
        mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.verified_at,
        )
        cleanup_time = self.verified_at + timedelta(days=8)
        inventory = inventory_migration_backups(self.db_path, now=cleanup_time)
        original_unlink = migration_backups._unlink_backup

        def interrupt_second(path: Path) -> None:
            if path == second:
                raise OSError("injected interruption")
            original_unlink(path)

        with patch.object(
            migration_backups,
            "_unlink_backup",
            side_effect=interrupt_second,
        ):
            interrupted = delete_verified_migration_backups(
                self.db_path,
                now=cleanup_time,
                expected_inventory_digest=inventory.inventory_digest,
                limit=2,
            )

        self.assertEqual(1, interrupted.deleted_count)
        self.assertFalse(interrupted.completed)
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())

        remaining = inventory_migration_backups(self.db_path, now=cleanup_time)
        resumed = delete_verified_migration_backups(
            self.db_path,
            now=cleanup_time,
            expected_inventory_digest=remaining.inventory_digest,
            limit=2,
        )
        self.assertEqual(1, resumed.deleted_count)
        self.assertTrue(resumed.completed)
        self.assertFalse(second.exists())

    def test_runtime_cancellation_stops_before_the_next_backup(self) -> None:
        first = self._create_backup(CURRENT_SCHEMA_VERSION - 2)
        second = self._create_backup(CURRENT_SCHEMA_VERSION - 1, ".1")
        for backup, version in (
            (first, CURRENT_SCHEMA_VERSION - 2),
            (second, CURRENT_SCHEMA_VERSION - 1),
        ):
            record_migration_backup(
                backup,
                source_schema_version=version,
                target_schema_version=CURRENT_SCHEMA_VERSION,
                runtime_version="test-runtime",
                now=self.created_at,
            )
        mark_migration_backups_verified(
            self.db_path,
            runtime_version="test-runtime",
            now=self.verified_at,
        )
        cleanup_time = self.verified_at + timedelta(days=8)
        inventory = inventory_migration_backups(self.db_path, now=cleanup_time)
        checks = 0

        def cancel_before_second() -> bool:
            nonlocal checks
            checks += 1
            return checks > 1

        with self.assertRaises(MigrationBackupError) as cancelled:
            delete_verified_migration_backups(
                self.db_path,
                now=cleanup_time,
                expected_inventory_digest=inventory.inventory_digest,
                limit=2,
                cancel_check=cancel_before_second,
            )

        self.assertEqual(
            "migration_backup_cleanup_cancelled",
            cancelled.exception.code,
        )
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        remaining = inventory_migration_backups(self.db_path, now=cleanup_time)
        self.assertEqual(1, remaining.eligible_count)

    def test_missing_old_generation_does_not_block_reusing_backup_name(self) -> None:
        version = CURRENT_SCHEMA_VERSION - 1
        old_backup = self._create_backup(version)
        record_migration_backup(
            old_backup,
            source_schema_version=version,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at,
        )
        old_backup.unlink()
        replacement = self._create_backup(version)

        record_migration_backup(
            replacement,
            source_schema_version=version,
            target_schema_version=CURRENT_SCHEMA_VERSION,
            runtime_version="test-runtime",
            now=self.created_at + timedelta(days=1),
        )

        state = json.loads(
            (self.data_dir / MIGRATION_BACKUP_STATE_FILENAME).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual([replacement.name], list(state["backups"]))
        self.assertEqual(
            "2026-08-02T12:00:00.000000Z",
            state["backups"][replacement.name]["created_at"],
        )


if __name__ == "__main__":
    unittest.main()
