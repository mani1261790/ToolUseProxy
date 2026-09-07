from __future__ import annotations

import gc
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from io import StringIO
from unittest.mock import patch

from hook_monitor.runtime.storage import EventStore
from tooluseproxy import automatic_cleanup
from tooluseproxy.automatic_cleanup import (
    AUTOMATIC_CLEANUP_INTERVAL,
    AUTOMATIC_CLEANUP_STATE_FILENAME,
    AutomaticCleanupError,
    automatic_cleanup_status,
    enable_automatic_cleanup,
    reserve_automatic_cleanup,
    run_automatic_cleanup,
    signal_runtime_activity,
    take_automatic_cleanup_notice,
)
from tooluseproxy.storage_cleanup import (
    STORAGE_ACTION_BYTES,
    StorageCleanupPlanError,
    apply_storage_cleanup,
    plan_storage_cleanup,
)
from tooluseproxy.cli import main as tooluseproxy_main


class AutomaticCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary.name) / "plugin-data"
        self.data_dir.mkdir(mode=0o700)
        self.db_path = self.data_dir / "events.db"
        EventStore(self.db_path).initialize()
        # Match a completed Hook process: release SQLite connections left for
        # cyclic garbage collection before reviewing a persisted plan.
        gc.collect()
        self.now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_old_sessions(self, count: int) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """
                INSERT INTO events (
                    event_id, phase, session_id, payload_json, recorded_at
                ) VALUES (?, 'stop', ?, '{}', '2026-07-01 00:00:00')
                """,
                ((f"event-{index}", f"session-{index}") for index in range(count)),
            )

    def _enable(self) -> dict[str, object]:
        plan = plan_storage_cleanup(self.db_path, now=self.now)
        return enable_automatic_cleanup(
            self.db_path,
            cutoff_at=plan.cutoff_at,
            reviewed_at=plan.reviewed_at,
            expected_plan_revision=plan.plan_revision,
            now=self.now,
        )

    def test_default_is_disabled_and_run_does_not_change_database(self) -> None:
        before = self.db_path.read_bytes()

        status = automatic_cleanup_status(self.data_dir)
        result = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )

        self.assertFalse(status["enabled"])
        self.assertEqual("never_run", status["status"])
        self.assertEqual("disabled", result.status)
        self.assertEqual(before, self.db_path.read_bytes())
        self.assertFalse(
            (self.data_dir / AUTOMATIC_CLEANUP_STATE_FILENAME).exists()
        )

    def test_enable_requires_the_exact_recent_reviewed_plan(self) -> None:
        plan = plan_storage_cleanup(self.db_path, now=self.now)
        with self.assertRaises(AutomaticCleanupError) as changed:
            enable_automatic_cleanup(
                self.db_path,
                cutoff_at=plan.cutoff_at,
                reviewed_at=plan.reviewed_at,
                expected_plan_revision="sc4_" + "0" * 64,
                now=self.now,
            )
        self.assertEqual(
            "automatic_cleanup_plan_changed",
            changed.exception.code,
        )
        with self.assertRaises(AutomaticCleanupError) as expired:
            enable_automatic_cleanup(
                self.db_path,
                cutoff_at=plan.cutoff_at,
                reviewed_at=plan.reviewed_at,
                expected_plan_revision=plan.plan_revision,
                now=self.now + timedelta(minutes=6),
            )
        self.assertEqual(
            "automatic_cleanup_plan_expired",
            expired.exception.code,
        )

        enabled_after_slow_plan = enable_automatic_cleanup(
            self.db_path,
            cutoff_at=plan.cutoff_at,
            reviewed_at="2026-09-07T12:10:00Z",
            expected_plan_revision=plan.plan_revision,
            now=self.now + timedelta(minutes=14),
        )
        self.assertTrue(enabled_after_slow_plan["enabled"])

        enabled = self._enable()

        self.assertTrue(enabled["enabled"])
        self.assertEqual("waiting", enabled["status"])
        self.assertEqual(
            0,
            (self.data_dir / AUTOMATIC_CLEANUP_STATE_FILENAME).stat().st_mode
            & 0o077,
        )

    def test_one_bounded_run_per_rolling_twenty_four_hours(self) -> None:
        self._seed_old_sessions(21)
        self._enable()

        first = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )
        first_status = automatic_cleanup_status(self.data_dir)
        before_boundary = run_automatic_cleanup(
            self.db_path,
            now=self.now + AUTOMATIC_CLEANUP_INTERVAL - timedelta(seconds=1),
            wait_for_quiet=False,
        )
        at_boundary = run_automatic_cleanup(
            self.db_path,
            now=self.now + AUTOMATIC_CLEANUP_INTERVAL,
            wait_for_quiet=False,
        )

        self.assertEqual("completed", first.status)
        self.assertEqual(20, first.deleted_session_count)
        self.assertEqual(1, first.remaining_session_count)
        self.assertEqual(
            1,
            first_status["remaining"]["session_count"],
        )
        self.assertEqual("not_due", before_boundary.status)
        self.assertEqual("completed", at_boundary.status)
        self.assertEqual(1, at_boundary.deleted_session_count)
        self.assertEqual(0, at_boundary.remaining_session_count)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_midnight_does_not_allow_a_second_run(self) -> None:
        started = datetime(2026, 9, 7, 23, 59, 30, tzinfo=UTC)
        plan = plan_storage_cleanup(self.db_path, now=started)
        enable_automatic_cleanup(
            self.db_path,
            cutoff_at=plan.cutoff_at,
            reviewed_at=plan.reviewed_at,
            expected_plan_revision=plan.plan_revision,
            now=started,
        )
        first = run_automatic_cleanup(
            self.db_path,
            now=started,
            wait_for_quiet=False,
        )
        after_midnight = run_automatic_cleanup(
            self.db_path,
            now=started + timedelta(minutes=2),
            wait_for_quiet=False,
        )

        self.assertEqual("completed", first.status)
        self.assertEqual("not_due", after_midnight.status)

    def test_busy_database_is_deferred_without_consuming_daily_run(self) -> None:
        self._seed_old_sessions(1)
        self._enable()
        blocker = sqlite3.connect(self.db_path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            deferred = run_automatic_cleanup(
                self.db_path,
                now=self.now,
                wait_for_quiet=False,
            )
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()

        self.assertEqual("deferred", deferred.status)
        self.assertEqual("database_busy", deferred.reason)
        resumed = run_automatic_cleanup(
            self.db_path,
            now=self.now + timedelta(minutes=5),
            wait_for_quiet=False,
        )
        self.assertEqual("completed", resumed.status)
        self.assertEqual(1, resumed.deleted_session_count)

    def test_recent_hook_activity_defers_and_preserves_records(self) -> None:
        self._seed_old_sessions(1)
        self._enable()
        signal_runtime_activity(self.data_dir)

        deferred = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )

        self.assertEqual("deferred", deferred.status)
        self.assertEqual("runtime_active", deferred.reason)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_failed_activity_signal_creates_a_fail_safe_defer(self) -> None:
        self._seed_old_sessions(1)
        self._enable()
        original_write = automatic_cleanup._atomic_write

        def fail_activity(path, data, **options):
            if path.name == automatic_cleanup.RUNTIME_ACTIVITY_FILENAME:
                raise AutomaticCleanupError("injected_activity_failure")
            return original_write(path, data, **options)

        with patch.object(
            automatic_cleanup,
            "_atomic_write",
            side_effect=fail_activity,
        ):
            with self.assertRaises(AutomaticCleanupError):
                signal_runtime_activity(self.data_dir)

        result = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )
        self.assertEqual("deferred", result.status)
        self.assertEqual("runtime_signal_failed", result.reason)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

        signal_runtime_activity(self.data_dir)
        self.assertFalse(
            (self.data_dir / automatic_cleanup.AUTOMATIC_CLEANUP_DEFER_FILENAME).exists()
        )

    def test_hook_signal_cancels_an_in_progress_deletion_transaction(self) -> None:
        self._seed_old_sessions(1)
        plan = plan_storage_cleanup(self.db_path, now=self.now)

        with self.assertRaises(StorageCleanupPlanError) as interrupted:
            apply_storage_cleanup(
                self.db_path,
                cutoff_at=plan.cutoff_at,
                expected_plan_revision=plan.plan_revision,
                cancel_check=lambda: True,
            )

        self.assertEqual("storage_cleanup_write_failed", interrupted.exception.code)
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_another_worker_causes_a_safe_defer(self) -> None:
        self._enable()
        with automatic_cleanup._automatic_cleanup_lock(
            self.data_dir,
            blocking=False,
        ) as acquired:
            self.assertTrue(acquired)
            result = run_automatic_cleanup(
                self.db_path,
                now=self.now,
                wait_for_quiet=False,
            )
        self.assertEqual("deferred", result.status)
        self.assertEqual("another_cleanup_running", result.reason)

    def test_interrupted_state_survives_restart_and_resumes_next_day(self) -> None:
        self._seed_old_sessions(1)
        self._enable()
        state = automatic_cleanup._load_state(self.data_dir, missing_ok=False)
        state.update(
            {
                "status": "running",
                "last_started_at": automatic_cleanup._format_time(self.now),
            }
        )
        automatic_cleanup._write_state(self.data_dir, state)

        same_day = run_automatic_cleanup(
            self.db_path,
            now=self.now + timedelta(hours=1),
            wait_for_quiet=False,
        )
        persisted = automatic_cleanup_status(self.data_dir)
        next_day = run_automatic_cleanup(
            self.db_path,
            now=self.now + AUTOMATIC_CLEANUP_INTERVAL,
            wait_for_quiet=False,
        )

        self.assertEqual("not_due", same_day.status)
        self.assertEqual("interrupted", persisted["status"])
        self.assertTrue(persisted["notification_pending"])
        self.assertEqual("completed", next_day.status)
        self.assertEqual(1, next_day.deleted_session_count)

    def test_forced_exit_leaves_recoverable_running_state(self) -> None:
        self._seed_old_sessions(1)
        self._enable()
        with patch.object(
            automatic_cleanup,
            "apply_storage_cleanup",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_automatic_cleanup(
                    self.db_path,
                    now=self.now,
                    wait_for_quiet=False,
                )

        persisted = automatic_cleanup_status(self.data_dir)
        self.assertEqual("running", persisted["status"])
        resumed = run_automatic_cleanup(
            self.db_path,
            now=self.now + AUTOMATIC_CLEANUP_INTERVAL,
            wait_for_quiet=False,
        )
        self.assertEqual("completed", resumed.status)
        self.assertEqual(1, resumed.deleted_session_count)

    def test_compaction_reclaims_free_pages_and_keeps_database_valid(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE synthetic_space (value BLOB)")
            conn.executemany(
                "INSERT INTO synthetic_space VALUES (?)",
                ((b"x" * 1024 * 1024,) for _ in range(20)),
            )
            conn.execute("DELETE FROM synthetic_space")
        before = self.db_path.stat().st_size
        self._enable()

        result = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )

        self.assertEqual("completed", result.status)
        self.assertTrue(result.database_compacted)
        self.assertLess(self.db_path.stat().st_size, before)
        EventStore(self.db_path).require_runtime_schema()
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])

    def test_hook_activity_interrupts_compaction_without_marking_failure(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE synthetic_space (value BLOB)")
            conn.executemany(
                "INSERT INTO synthetic_space VALUES (?)",
                ((b"x" * 1024 * 1024,) for _ in range(20)),
            )
            conn.execute("DELETE FROM synthetic_space")
        self._enable()

        def interrupted_compaction(*args, **kwargs):
            signal_runtime_activity(self.data_dir)
            return False

        with patch.object(
            automatic_cleanup,
            "_compact_database",
            side_effect=interrupted_compaction,
        ):
            result = run_automatic_cleanup(
                self.db_path,
                now=self.now,
                wait_for_quiet=False,
            )

        self.assertEqual("deferred", result.status)
        self.assertEqual("runtime_active", result.reason)
        self.assertFalse(automatic_cleanup_status(self.data_dir)["notification_pending"])
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual("ok", conn.execute("PRAGMA quick_check").fetchone()[0])

    def test_insufficient_space_keeps_database_and_sets_one_notice(self) -> None:
        self._enable()
        plan = plan_storage_cleanup(self.db_path, now=self.now)
        constrained = replace(
            plan,
            database_free_page_bytes=automatic_cleanup.COMPACTION_MINIMUM_FREE_BYTES,
            temporary_space_available_bytes=0,
            temporary_space_required_bytes=1,
        )
        with patch.object(
            automatic_cleanup,
            "plan_storage_cleanup",
            return_value=constrained,
        ):
            result = run_automatic_cleanup(
                self.db_path,
                now=self.now,
                wait_for_quiet=False,
            )

        self.assertEqual("completed_with_warning", result.status)
        self.assertEqual("insufficient_temporary_space", result.reason)
        notice = take_automatic_cleanup_notice(self.data_dir)
        self.assertIn("空き容量", notice or "")
        self.assertIsNone(take_automatic_cleanup_notice(self.data_dir))

    def test_four_gib_after_cleanup_sets_action_state_and_notice(self) -> None:
        self._enable()
        plan = replace(
            plan_storage_cleanup(self.db_path, now=self.now),
            database_allocated_bytes=STORAGE_ACTION_BYTES,
        )
        with patch.object(
            automatic_cleanup,
            "plan_storage_cleanup",
            return_value=plan,
        ):
            result = run_automatic_cleanup(
                self.db_path,
                now=self.now,
                wait_for_quiet=False,
            )

        self.assertEqual("action_required", result.storage_level)
        self.assertTrue(automatic_cleanup_status(self.data_dir)["notification_pending"])
        self.assertIn("4 GiB", take_automatic_cleanup_notice(self.data_dir) or "")

    def test_normal_run_preserves_an_unread_prior_notice(self) -> None:
        self._enable()
        state = automatic_cleanup._load_state(self.data_dir, missing_ok=False)
        state["notification_pending"] = "cleanup_failed"
        automatic_cleanup._write_state(self.data_dir, state)

        result = run_automatic_cleanup(
            self.db_path,
            now=self.now,
            wait_for_quiet=False,
        )

        self.assertEqual("completed", result.status)
        self.assertTrue(automatic_cleanup_status(self.data_dir)["notification_pending"])
        self.assertIn("完了できませんでした", take_automatic_cleanup_notice(self.data_dir) or "")

    def test_reservation_only_writes_request_and_starts_detached_worker(self) -> None:
        self._enable()
        with patch.object(automatic_cleanup.subprocess, "Popen") as popen:
            started = reserve_automatic_cleanup(self.db_path)

        self.assertTrue(started)
        self.assertTrue(
            (self.data_dir / automatic_cleanup.AUTOMATIC_CLEANUP_REQUEST_FILENAME).is_file()
        )
        command = popen.call_args.args[0]
        self.assertEqual(
            ["storage", "cleanup", "auto", "run"],
            command[-7:-3],
        )
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_cli_enable_status_run_and_disable_are_value_free(self) -> None:
        plan = plan_storage_cleanup(self.db_path)

        def run(arguments: list[str]) -> tuple[int, dict[str, object], str]:
            output = StringIO()
            with redirect_stdout(output):
                exit_code = tooluseproxy_main(arguments)
            return exit_code, json.loads(output.getvalue()), output.getvalue()

        common = ["--data-dir", str(self.data_dir), "--json"]
        enabled_code, enabled, enabled_text = run(
            [
                "storage",
                "cleanup",
                "auto",
                "enable",
                "--cutoff-at",
                plan.cutoff_at,
                "--reviewed-at",
                plan.reviewed_at,
                "--plan-revision",
                plan.plan_revision,
                *common,
            ]
        )
        status_code, status, status_text = run(
            ["storage", "cleanup", "auto", "status", *common]
        )
        run_code, worker, worker_text = run(
            ["storage", "cleanup", "auto", "run", *common]
        )
        disabled_code, disabled, disabled_text = run(
            ["storage", "cleanup", "auto", "disable", *common]
        )

        self.assertEqual((0, 0, 0, 0), (
            enabled_code, status_code, run_code, disabled_code,
        ))
        self.assertTrue(enabled["enabled"])
        self.assertTrue(status["enabled"])
        self.assertEqual("completed", worker["status"])
        self.assertFalse(disabled["enabled"])
        rendered = enabled_text + status_text + worker_text + disabled_text
        self.assertNotIn(str(self.data_dir), rendered)
        self.assertNotIn("events.db", rendered)


if __name__ == "__main__":
    unittest.main()
