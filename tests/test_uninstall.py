from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from hook_monitor.runtime.storage import EventStore
from tooluseproxy.cli import main as cli_main
from tooluseproxy.uninstall import DATA_DIRECTORY_MARKER, ensure_data_directory_marker


def _run_cli(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli_main(arguments)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class UninstallCliTest(unittest.TestCase):
    def test_data_marker_is_private_idempotent_and_value_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "plugin-data"
            data_dir.mkdir(mode=0o700)
            marker = ensure_data_directory_marker(data_dir)
            first = marker.read_bytes()
            self.assertEqual(marker, ensure_data_directory_marker(data_dir))
            self.assertEqual(first, marker.read_bytes())
            payload = json.loads(first)
            self.assertEqual("ToolUseProxy", payload["product"])
            if os.name == "posix":
                self.assertEqual(0o600, marker.stat().st_mode & 0o777)

    def test_plan_for_missing_directory_changes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "missing"
            exit_code, stdout, stderr = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            self.assertEqual(0, exit_code, stderr)
            payload = json.loads(stdout)
            self.assertEqual("nothing_to_delete", payload["status"])
            self.assertIsNone(payload["confirmation_token"])
            self.assertFalse(data_dir.exists())

    def test_apply_deletes_managed_data_and_retains_unmanaged_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "plugin-data"
            data_dir.mkdir(mode=0o700)
            ensure_data_directory_marker(data_dir)
            (data_dir / "events.db").write_bytes(b"database")
            (data_dir / "events.db-wal").write_bytes(b"wal")
            (data_dir / "events.db.pre-migration-v3.bak").write_bytes(b"backup")
            backup_dir = data_dir / "manifest-backups" / "workspace"
            backup_dir.mkdir(parents=True)
            (backup_dir / "protected_sources.json").write_text(
                '{"protected": true}\n', encoding="utf-8"
            )
            unmanaged = data_dir / "operator-note.txt"
            unmanaged.write_text("retain me\n", encoding="utf-8")

            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            self.assertEqual(0, planned[0], planned[2])
            plan = json.loads(planned[1])
            self.assertEqual("review_required", plan["status"])
            self.assertEqual(1, plan["unmanaged_entry_count"])
            self.assertGreater(plan["managed_file_count"], 0)
            self.assertNotIn("protected", planned[1])
            self.assertNotIn("retain me", planned[1])

            applied = _run_cli(
                [
                    "uninstall",
                    "apply",
                    "--data-dir",
                    str(data_dir),
                    "--confirmation-token",
                    plan["confirmation_token"],
                    "--json",
                ]
            )
            self.assertEqual(0, applied[0], applied[2])
            result = json.loads(applied[1])
            self.assertEqual("deleted", result["status"])
            self.assertTrue(result["unmanaged_entries_retained"])
            self.assertFalse(result["data_directory_removed"])
            self.assertEqual("retain me\n", unmanaged.read_text(encoding="utf-8"))
            self.assertFalse((data_dir / "events.db").exists())
            self.assertFalse((data_dir / "manifest-backups").exists())

    def test_apply_rejects_stale_confirmation_without_deleting_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "plugin-data"
            data_dir.mkdir(mode=0o700)
            ensure_data_directory_marker(data_dir)
            database = data_dir / "events.db"
            database.write_bytes(b"before")
            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            token = json.loads(planned[1])["confirmation_token"]
            database.write_bytes(b"after")

            applied = _run_cli(
                [
                    "uninstall",
                    "apply",
                    "--data-dir",
                    str(data_dir),
                    "--confirmation-token",
                    token,
                    "--json",
                ]
            )
            self.assertEqual(1, applied[0])
            self.assertIn("changed after review", applied[2])
            self.assertEqual(b"after", database.read_bytes())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_plan_rejects_symlinks_inside_managed_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_dir = root / "plugin-data"
            backup_dir = data_dir / "manifest-backups"
            backup_dir.mkdir(parents=True, mode=0o700)
            data_dir.chmod(0o700)
            ensure_data_directory_marker(data_dir)
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (backup_dir / "link").symlink_to(outside)

            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            self.assertEqual(1, planned[0])
            self.assertIn("contains a symlink", planned[2])
            self.assertEqual("outside\n", outside.read_text(encoding="utf-8"))

    def test_apply_removes_an_empty_dedicated_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "plugin-data"
            data_dir.mkdir(mode=0o700)
            ensure_data_directory_marker(data_dir)
            (data_dir / "events.db").write_bytes(b"database")
            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            token = json.loads(planned[1])["confirmation_token"]
            applied = _run_cli(
                [
                    "uninstall",
                    "apply",
                    "--data-dir",
                    str(data_dir),
                    "--confirmation-token",
                    token,
                    "--json",
                ]
            )
            self.assertEqual(0, applied[0], applied[2])
            self.assertTrue(json.loads(applied[1])["data_directory_removed"])
            self.assertFalse(data_dir.exists())

    def test_plan_refuses_an_unidentified_database_with_the_same_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "other-application"
            data_dir.mkdir(mode=0o700)
            database = data_dir / "events.db"
            database.write_bytes(b"not ToolUseProxy")

            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            self.assertEqual(1, planned[0])
            self.assertIn("not identifiable", planned[2])
            self.assertEqual(b"not ToolUseProxy", database.read_bytes())

    def test_legacy_database_without_marker_is_still_identified_by_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            data_dir = Path(temporary_directory) / "legacy-plugin-data"
            data_dir.mkdir(mode=0o700)
            EventStore(data_dir / "events.db").initialize()
            self.assertFalse((data_dir / DATA_DIRECTORY_MARKER).exists())

            planned = _run_cli(
                ["uninstall", "plan", "--data-dir", str(data_dir), "--json"]
            )
            self.assertEqual(0, planned[0], planned[2])
            self.assertEqual("review_required", json.loads(planned[1])["status"])


if __name__ == "__main__":
    unittest.main()
