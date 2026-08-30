from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from hook_monitor.runtime.source_config import CURRENT_MANIFEST_SCHEMA_VERSION
from tooluseproxy.cli import main as cli_main


class ProtectedSourceMigrationCliTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "manifest migration is POSIX-only")
    def test_plan_apply_and_retry_use_the_exact_value_free_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, workspace, data_dir = self._initialized_workspace(
                Path(temporary_directory)
            )
            sentinel = "C.MIGRATION.MANIFEST.UNKNOWN.VALUE"
            manifest_path = workspace / "protected_sources.json"
            before = (
                json.dumps(
                    {
                        "sources": [],
                        "unknown_metadata": {"private_label": sentinel},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            ).encode("utf-8")
            manifest_path.write_bytes(before)
            manifest_path.chmod(0o600)

            plan_stdout = io.StringIO()
            plan_stderr = io.StringIO()
            with redirect_stdout(plan_stdout), redirect_stderr(plan_stderr):
                plan_exit = cli_main(
                    [
                        "protect",
                        "migrate",
                        "plan",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(0, plan_exit, plan_stderr.getvalue())
            plan = json.loads(plan_stdout.getvalue())
            self.assertEqual("review_required", plan["status"])
            self.assertEqual(1, plan["from_schema_version"])
            self.assertTrue(plan["schema_version_was_omitted"])
            self.assertEqual(2, plan["to_schema_version"])
            self.assertEqual(0, plan["source_count"])
            self.assertFalse(plan["sources_field_will_be_added"])
            self.assertEqual(0, plan["selector_changes"])
            self.assertEqual("utf8_2_space_lf", plan["formatting_policy"])
            self.assertTrue(plan["review_required"])
            self.assertEqual(hashlib.sha256(before).hexdigest(), plan["manifest_sha256"])
            self.assertRegex(plan["migration_id"], r"[0-9a-f]{32}\Z")
            self.assertTrue(plan["migration_revision"])
            self.assertNotEqual(
                plan["manifest_sha256"],
                plan["result_manifest_sha256"],
            )
            self.assertNotIn(sentinel, plan_stdout.getvalue())
            self.assertNotIn(sentinel, plan_stderr.getvalue())
            backup_path = data_dir / plan["backup_relative_path"]
            self.assertFalse(backup_path.exists())

            apply_arguments = [
                "protect",
                "migrate",
                "apply",
                "--migration-revision",
                plan["migration_revision"],
                "--expected-manifest-sha256",
                plan["manifest_sha256"],
                "--workspace",
                str(workspace),
                "--data-dir",
                str(data_dir),
                "--json",
            ]
            apply_stdout = io.StringIO()
            apply_stderr = io.StringIO()
            with redirect_stdout(apply_stdout), redirect_stderr(apply_stderr):
                apply_exit = cli_main(apply_arguments)

            self.assertEqual(0, apply_exit, apply_stderr.getvalue())
            applied = json.loads(apply_stdout.getvalue())
            self.assertEqual("migrated", applied["status"])
            self.assertEqual(plan["migration_id"], applied["migration_id"])
            self.assertEqual(
                plan["result_manifest_sha256"],
                applied["manifest_sha256"],
            )
            self.assertNotIn(sentinel, apply_stdout.getvalue())
            self.assertNotIn(sentinel, apply_stderr.getvalue())
            self.assertEqual(before, backup_path.read_bytes())
            self.assertEqual(
                0o600,
                stat.S_IMODE(backup_path.stat().st_mode),
            )
            migrated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(2, migrated_manifest["schema_version"])
            self.assertEqual([], migrated_manifest["sources"])
            self.assertEqual(
                {"private_label": sentinel},
                migrated_manifest["unknown_metadata"],
            )
            self.assertEqual(
                plan["result_manifest_sha256"],
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            )

            retry_stdout = io.StringIO()
            retry_stderr = io.StringIO()
            with redirect_stdout(retry_stdout), redirect_stderr(retry_stderr):
                retry_exit = cli_main(apply_arguments)
            self.assertEqual(0, retry_exit, retry_stderr.getvalue())
            self.assertEqual(
                "already_migrated",
                json.loads(retry_stdout.getvalue())["status"],
            )
            self.assertEqual(before, backup_path.read_bytes())

            with sqlite3.connect(data_dir / "events.db") as connection:
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT COUNT(*) FROM protected_source_candidates"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT COUNT(*) FROM protected_source_candidate_reviews"
                    ).fetchone()[0],
                )

    def test_doctor_and_status_keep_a_legacy_manifest_runtime_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, workspace, data_dir = self._initialized_workspace(
                Path(temporary_directory)
            )
            sentinel = "C.MIGRATION.STATUS.MUST.NOT.LEAK"
            manifest_path = workspace / "protected_sources.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "sources": [],
                        "unknown_metadata": sentinel,
                    }
                ),
                encoding="utf-8",
            )
            if os.name == "posix":
                manifest_path.chmod(0o600)

            reports: dict[str, dict[str, object]] = {}
            for command, expected_status in (("doctor", "ok"), ("status", "inactive")):
                with self.subTest(command=command):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        exit_code = cli_main(
                            [
                                command,
                                "--workspace",
                                str(workspace),
                                "--data-dir",
                                str(data_dir),
                                "--json",
                            ]
                        )
                    self.assertEqual(
                        0 if command == "doctor" else 1,
                        exit_code,
                        stdout.getvalue(),
                    )
                    report = json.loads(stdout.getvalue())
                    self.assertEqual(expected_status, report["status"])
                    self.assertNotIn(sentinel, stdout.getvalue())
                    reports[command] = report

            for report in reports.values():
                protected_sources = report["protected_sources"]
                self.assertEqual(1, protected_sources["schema_version"])
                self.assertTrue(protected_sources["ok"])
                self.assertTrue(protected_sources["runtime_readable"])
                self.assertFalse(protected_sources["registration_writable"])
                self.assertTrue(protected_sources["migration_required"])

    def test_status_reports_a_v2_manifest_as_registration_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, workspace, data_dir = self._initialized_workspace(
                Path(temporary_directory)
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "status",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(1, exit_code, stdout.getvalue())
            report = json.loads(stdout.getvalue())
            self.assertEqual("inactive", report["status"])
            self.assertEqual(
                {
                    "ok": True,
                    "detail": "manifest valid; protected sources=0 source chunks=0",
                    "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                    "runtime_readable": True,
                    "registration_writable": True,
                    "migration_required": False,
                },
                report["protected_sources"],
            )

    def test_status_does_not_claim_runtime_readable_non_strict_json_is_writable(
        self,
    ) -> None:
        manifests = {
            "duplicate-key": (
                '{"schema_version":2,"sources":[],"metadata":1,"metadata":2}\n'
            ),
            "non-finite-number": (
                '{"schema_version":2,"sources":[],"metadata":NaN}\n'
            ),
        }
        for case, manifest in manifests.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                _, workspace, data_dir = self._initialized_workspace(
                    Path(temporary_directory)
                )
                manifest_path = workspace / "protected_sources.json"
                manifest_path.write_text(manifest, encoding="utf-8")
                if os.name == "posix":
                    manifest_path.chmod(0o600)

                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = cli_main(
                        [
                            "status",
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    )

                self.assertEqual(1, exit_code, stdout.getvalue())
                report = json.loads(stdout.getvalue())
                self.assertEqual("inactive", report["status"])
                protected_sources = report["protected_sources"]
                self.assertTrue(protected_sources["runtime_readable"])
                self.assertFalse(protected_sources["registration_writable"])
                self.assertFalse(protected_sources["migration_required"])
                self.assertNotIn("metadata", protected_sources["detail"])

    @unittest.skipUnless(os.name == "posix", "link semantics are POSIX-only")
    def test_status_does_not_claim_linked_manifest_is_registration_writable(self) -> None:
        for link_kind in ("symlink", "hardlink"):
            with (
                self.subTest(link_kind=link_kind),
                tempfile.TemporaryDirectory() as temporary_directory,
            ):
                _, workspace, data_dir = self._initialized_workspace(
                    Path(temporary_directory)
                )
                manifest_path = workspace / "protected_sources.json"
                linked_target = workspace / "linked-manifest.json"
                manifest_path.rename(linked_target)
                if link_kind == "symlink":
                    manifest_path.symlink_to(linked_target.name)
                else:
                    os.link(linked_target, manifest_path)

                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = cli_main(
                        [
                            "status",
                            "--workspace",
                            str(workspace),
                            "--data-dir",
                            str(data_dir),
                            "--json",
                        ]
                    )

                self.assertEqual(1, exit_code, stdout.getvalue())
                report = json.loads(stdout.getvalue())
                self.assertEqual("inactive", report["status"])
                protected_sources = report["protected_sources"]
                self.assertTrue(protected_sources["runtime_readable"])
                self.assertFalse(protected_sources["registration_writable"])
                self.assertFalse(protected_sources["migration_required"])

    def test_status_exposes_an_invalid_schema_without_marking_it_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, workspace, data_dir = self._initialized_workspace(
                Path(temporary_directory)
            )
            manifest_path = workspace / "protected_sources.json"
            manifest_path.write_text(
                json.dumps({"schema_version": 99, "sources": []}),
                encoding="utf-8",
            )
            if os.name == "posix":
                manifest_path.chmod(0o600)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "status",
                        "--workspace",
                        str(workspace),
                        "--data-dir",
                        str(data_dir),
                        "--json",
                    ]
                )

            self.assertEqual(1, exit_code)
            report = json.loads(stdout.getvalue())
            self.assertEqual("inactive", report["status"])
            protected_sources = report["protected_sources"]
            self.assertEqual(99, protected_sources["schema_version"])
            self.assertFalse(protected_sources["ok"])
            self.assertFalse(protected_sources["runtime_readable"])
            self.assertFalse(protected_sources["registration_writable"])
            self.assertFalse(protected_sources["migration_required"])

    @staticmethod
    def _initialized_workspace(root: Path) -> tuple[Path, Path, Path]:
        workspace = root / "workspace"
        data_dir = root / "data"
        workspace.mkdir()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "init",
                    "--workspace",
                    str(workspace),
                    "--data-dir",
                    str(data_dir),
                    "--json",
                ]
            )
        if exit_code != 0:
            raise AssertionError(stderr.getvalue())
        return root, workspace, data_dir


if __name__ == "__main__":
    unittest.main()
