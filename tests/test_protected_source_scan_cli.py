from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tooluseproxy.cli import (
    _scan_excluded_relative_paths,
    main as cli_main,
)
from tooluseproxy.paths import RuntimePaths
from tooluseproxy.protected_sources import (
    DETECTOR_VERSION,
    LEGACY_DETECTOR_VERSION,
    scan_protected_sources,
)


@unittest.skipIf(os.name == "nt", "protected-source scan is POSIX-only")
class ProtectedSourceScanCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self._temporary_directory.name)
        self.workspace = root / "workspace"
        self.data_dir = root / "runtime-data"
        self.workspace.mkdir()
        exit_code, payload, stderr = self._run_json(
            "init",
            "--codex",
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        )
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("initialized", payload["status"])

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @property
    def manifest_path(self) -> Path:
        return self.workspace / "protected_sources.json"

    def _run_raw(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_main(list(arguments))
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _run_json(
        self,
        *arguments: str,
    ) -> tuple[int, dict[str, object], str]:
        exit_code, stdout, stderr = self._run_raw(*arguments)
        payload = json.loads(stdout) if stdout else {}
        self.assertIsInstance(payload, dict)
        return exit_code, payload, stderr

    def _protect_arguments(self, action: str, *arguments: str) -> tuple[str, ...]:
        return (
            "protect",
            action,
            *arguments,
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
            "--json",
        )

    def _scan(self) -> tuple[dict[str, object], str]:
        exit_code, payload, stderr = self._run_json(*self._protect_arguments("scan"))
        self.assertEqual(0, exit_code, stderr)
        return payload, stderr

    def _single_candidate(
        self,
        payload: dict[str, object],
    ) -> dict[str, object]:
        self.assertEqual("review_required", payload["status"])
        self.assertGreaterEqual(payload["candidate_count"], 1)
        candidates = payload["candidates"]
        self.assertIsInstance(candidates, list)
        self.assertGreaterEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertIsInstance(candidate, dict)
        return candidate

    def _review_batch(
        self,
        payload: dict[str, object],
        decisions: tuple[tuple[dict[str, object], str], ...],
    ) -> tuple[int, dict[str, object], str]:
        arguments: list[str] = []
        for candidate, decision in decisions:
            arguments.extend(
                (
                    "--decision",
                    str(candidate["candidate_id"]),
                    str(candidate["candidate_revision"]),
                    decision,
                )
            )
        arguments.extend(
            (
                "--expected-manifest-sha256",
                str(payload["manifest_sha256"]),
            )
        )
        return self._run_json(*self._protect_arguments("review", *arguments))

    def _approve(
        self,
        payload: dict[str, object],
        candidate: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        return self._run_json(
            *self._protect_arguments(
                "approve",
                str(candidate["candidate_id"]),
                "--candidate-revision",
                str(candidate["candidate_revision"]),
                "--expected-manifest-sha256",
                str(payload["manifest_sha256"]),
            )
        )

    def _reject(
        self,
        candidate: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        return self._run_json(
            *self._protect_arguments(
                "reject",
                str(candidate["candidate_id"]),
                "--candidate-revision",
                str(candidate["candidate_revision"]),
            )
        )

    def _ignore(
        self,
        candidate: dict[str, object],
    ) -> tuple[int, dict[str, object], str]:
        return self._run_json(
            *self._protect_arguments(
                "ignore",
                str(candidate["candidate_id"]),
                "--candidate-revision",
                str(candidate["candidate_revision"]),
            )
        )

    def _write_json_source(self, relative_path: str, secret: str) -> Path:
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "private_token": secret,
                    "public_mode": "demo",
                }
            ),
            encoding="utf-8",
        )
        return path

    def _database_text(self) -> str:
        values: list[str] = []
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for (table_name,) in tables:
                columns = conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
                names = [str(row[1]) for row in columns]
                if not names:
                    continue
                quoted = ", ".join(f'"{name}"' for name in names)
                for row in conn.execute(f'SELECT {quoted} FROM "{table_name}"'):
                    values.extend(str(value) for value in row if value is not None)
        return "\n".join(values)

    def _rewrite_candidate_detector_version(
        self,
        candidate_id: str,
        detector_version: str,
    ) -> None:
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            row = conn.execute(
                """
                SELECT workspace_id, relative_path, source_sha256,
                       proposed_source_json
                FROM protected_source_candidates
                WHERE candidate_id = ?
                """,
                (candidate_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            workspace_id, relative_path, source_sha256, proposed_source_json = row
            fingerprint_payload = {
                "detector_version": detector_version,
                "workspace_id": workspace_id,
                "path": relative_path,
                "source_sha256": source_sha256,
                "proposed_source": json.loads(proposed_source_json),
            }
            suppression_fingerprint = hashlib.sha256(
                json.dumps(
                    fingerprint_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            conn.execute(
                """
                UPDATE protected_source_candidates
                SET detector_version = ?, suppression_fingerprint = ?
                WHERE candidate_id = ?
                """,
                (detector_version, suppression_fingerprint, candidate_id),
            )

    def _candidate_storage_snapshot(
        self,
        candidate_id: str,
    ) -> tuple[tuple[object, ...], tuple[tuple[object, ...], ...]]:
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            candidate = conn.execute(
                "SELECT * FROM protected_source_candidates WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
            reviews = tuple(
                conn.execute(
                    "SELECT * FROM protected_source_candidate_reviews "
                    "WHERE candidate_id = ? ORDER BY rowid",
                    (candidate_id,),
                ).fetchall()
            )
        self.assertIsNotNone(candidate)
        return candidate, reviews

    def _bury_candidate_beyond_recent_history(self, candidate_id: str) -> None:
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            row = conn.execute(
                "SELECT workspace_id, manifest_sha256 "
                "FROM protected_source_candidates WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            workspace_id, manifest_sha256 = row
            conn.execute(
                "UPDATE protected_source_candidates "
                "SET created_at = '2000-01-01 00:00:00' WHERE candidate_id = ?",
                (candidate_id,),
            )
            filler_rows = []
            for index in range(1024):
                seed = f"candidate-history-{index}".encode()
                relative_path = f"history/{index:04d}.json"
                filler_rows.append(
                    (
                        hashlib.sha256(b"id:" + seed).hexdigest()[:32],
                        hashlib.sha256(b"revision:" + seed).hexdigest(),
                        workspace_id,
                        relative_path,
                        "history-fixture-v1",
                        "bounded_scan",
                        '["history_fixture"]',
                        0.5,
                        json.dumps(
                            {
                                "id": f"history-{index:04d}",
                                "path": relative_path,
                                "type": "secretfile",
                                "sensitivity": "high",
                                "selector": {"json_pointers": ["/private_token"]},
                            },
                            sort_keys=True,
                        ),
                        hashlib.sha256(b"source:" + seed).hexdigest(),
                        1,
                        1,
                        manifest_sha256,
                        hashlib.sha256(b"fingerprint:" + seed).hexdigest(),
                    )
                )
            conn.executemany(
                """
                INSERT INTO protected_source_candidates (
                    candidate_id,
                    candidate_revision_sha256,
                    workspace_id,
                    relative_path,
                    detector_version,
                    discovery_source,
                    rule_ids_json,
                    confidence,
                    proposed_source_json,
                    source_sha256,
                    source_size,
                    source_mtime_ns,
                    manifest_sha256,
                    suppression_fingerprint,
                    status,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'rejected', '2100-01-01 00:00:00', '2100-01-01 00:00:00')
                """,
                filler_rows,
            )
            recent_candidate_ids = {
                value
                for (value,) in conn.execute(
                    "SELECT candidate_id FROM protected_source_candidates "
                    "ORDER BY created_at DESC, candidate_id DESC LIMIT 1024"
                )
            }
        self.assertNotIn(candidate_id, recent_candidate_ids)

    def test_scan_is_value_free_bounded_and_does_not_mutate_the_manifest(self) -> None:
        secret = "SCAN.JSON.SECRET.28a4"
        source = self._write_json_source("config/runtime.json", secret)
        manifest_before = self.manifest_path.read_bytes()

        payload, stderr = self._scan()
        candidate = self._single_candidate(payload)

        self.assertEqual(1, payload["schema_version"])
        self.assertTrue(payload["scan_complete"])
        self.assertEqual([], payload["truncation_reasons"])
        self.assertEqual(
            {
                "max_depth": 8,
                "max_entries": 20_000,
                "max_files": 10_000,
                "max_eligible_files": 512,
                "max_total_read_bytes": 16 * 1024 * 1024,
                "max_candidates": 64,
                "max_public_metadata_bytes": 512 * 1024,
            },
            payload["scan_limits"],
        )
        self.assertEqual("batch", payload["approval_mode"])
        self.assertEqual(10, payload["review_batch_limit"])
        self.assertFalse(payload["rescan_required_after_manifest_change"])
        self.assertEqual(0, payload["remaining_candidate_count"])
        self.assertTrue(payload["continuation_required"])
        self.assertEqual("config/runtime.json", candidate["path"])
        self.assertEqual(
            {"json_pointers": ["/private_token"]},
            candidate["proposed_source"]["selector"],
        )
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        self.assertEqual(
            hashlib.sha256(manifest_before).hexdigest(),
            payload["manifest_sha256"],
        )
        rendered = json.dumps(payload, ensure_ascii=False)
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertNotIn(secret, rendered)
        self.assertNotIn(secret, stderr)
        self.assertNotIn(str(self.workspace.resolve()), rendered)
        self.assertNotIn(source_sha256, rendered)
        self.assertNotIn(secret, self._database_text())
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            stored = conn.execute(
                "SELECT discovery_source FROM protected_source_candidates"
            ).fetchall()
        self.assertEqual([("bounded_scan",)], stored)

    def test_batch_review_applies_multiple_candidates_without_user_rescan(self) -> None:
        self._write_json_source("config/a.json", "SCAN.FIRST.SECRET.8a12")
        self._write_json_source("config/z.json", "SCAN.SECOND.SECRET.12f8")

        first_scan, _ = self._scan()
        candidates = first_scan["candidates"]
        self.assertIsInstance(candidates, list)
        self.assertEqual(2, len(candidates))
        first, second = candidates
        self.assertEqual("config/a.json", first["path"])
        self.assertEqual("config/z.json", second["path"])
        self.assertEqual(0, first_scan["remaining_candidate_count"])
        self.assertTrue(first_scan["continuation_required"])

        exit_code, approved, stderr = self._review_batch(
            first_scan,
            ((first, "approve"), (second, "approve")),
        )
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("reviewed", approved["status"])
        self.assertEqual(2, approved["approved_count"])
        final_scan, _ = self._scan()
        self.assertEqual("no_candidate", final_scan["status"])
        self.assertEqual([], final_scan["candidates"])
        self.assertGreaterEqual(final_scan["already_registered_count"], 2)
        self.assertFalse(final_scan["continuation_required"])
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            ["config/a.json", "config/z.json"],
            [source["path"] for source in manifest["sources"]],
        )

    def test_batch_review_applies_mixed_decisions_in_one_command(self) -> None:
        for name in ("a", "b", "c"):
            self._write_json_source(
                f"config/{name}.json",
                f"SCAN.MIXED.{name}.SECRET.71c2",
            )
        scan, _ = self._scan()
        candidates = scan["candidates"]
        self.assertIsInstance(candidates, list)
        self.assertEqual(3, len(candidates))

        exit_code, reviewed, stderr = self._review_batch(
            scan,
            (
                (candidates[0], "approve"),
                (candidates[1], "reject"),
                (candidates[2], "ignore"),
            ),
        )

        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("reviewed", reviewed["status"])
        self.assertEqual(1, reviewed["approved_count"])
        self.assertEqual(1, reviewed["rejected_count"])
        self.assertEqual(1, reviewed["ignored_count"])
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(["config/a.json"], [item["path"] for item in manifest["sources"]])
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            statuses = dict(
                conn.execute(
                    "SELECT relative_path, status FROM protected_source_candidates"
                ).fetchall()
            )
        self.assertEqual(
            {
                "config/a.json": "approved",
                "config/b.json": "rejected",
                "config/c.json": "ignored",
            },
            statuses,
        )

    def test_batch_review_source_change_stops_before_manifest_mutation(self) -> None:
        first_path = self._write_json_source(
            "config/a.json",
            "SCAN.STALE.A.SECRET.41d2",
        )
        self._write_json_source("config/b.json", "SCAN.STALE.B.SECRET.52e3")
        scan, _ = self._scan()
        candidates = scan["candidates"]
        self.assertIsInstance(candidates, list)
        manifest_before = self.manifest_path.read_bytes()
        first_path.write_text(
            json.dumps({"private_token": "changed"}),
            encoding="utf-8",
        )

        exit_code, payload, stderr = self._review_batch(
            scan,
            tuple((candidate, "approve") for candidate in candidates),
        )

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertEqual("source_changed", json.loads(stderr)["error"]["code"])
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            statuses = {
                row[0]
                for row in conn.execute("SELECT status FROM protected_source_candidates").fetchall()
            }
        self.assertEqual({"stale"}, statuses)

    def test_scan_limits_one_review_batch_to_ten_candidates(self) -> None:
        for index in range(11):
            self._write_json_source(
                f"config/{index:02d}.json",
                f"SCAN.PAGE.{index:02d}.SECRET.83f1",
            )

        scan, _ = self._scan()

        self.assertEqual(10, scan["candidate_count"])
        self.assertEqual(1, scan["remaining_candidate_count"])
        self.assertEqual(
            [f"config/{index:02d}.json" for index in range(10)],
            [candidate["path"] for candidate in scan["candidates"]],
        )

    def test_rejected_candidate_is_suppressed_before_the_next_candidate(self) -> None:
        self._write_json_source("config/a.json", "SCAN.REJECT.SECRET.6f19")
        self._write_json_source("config/z.json", "SCAN.NEXT.SECRET.8c20")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)

        exit_code, rejected, stderr = self._reject(first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("rejected", rejected["status"])

        second_scan, _ = self._scan()
        second = self._single_candidate(second_scan)
        self.assertEqual("config/z.json", second["path"])
        self.assertEqual(1, second_scan["suppressed_count"])
        self.assertEqual(0, second_scan["remaining_candidate_count"])

    def test_rejected_candidate_is_suppressed_beyond_recent_history_limit(self) -> None:
        self._write_json_source("config/runtime.json", "SCAN.OLD.REJECT.8a20")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        exit_code, rejected, stderr = self._reject(first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("rejected", rejected["status"])
        self._bury_candidate_beyond_recent_history(str(first["candidate_id"]))

        second_scan, _ = self._scan()

        self.assertEqual("suppressed", second_scan["status"])
        self.assertEqual([], second_scan["candidates"])
        self.assertEqual(1, second_scan["suppressed_count"])
        self.assertEqual(0, second_scan["remaining_candidate_count"])

    def test_rescan_rotates_revision_and_invalidates_the_old_output(self) -> None:
        self._write_json_source("config/runtime.json", "SCAN.ROTATE.SECRET.7b19")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        second_scan, _ = self._scan()
        second = self._single_candidate(second_scan)

        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertNotEqual(first["candidate_revision"], second["candidate_revision"])
        exit_code, payload, stderr = self._approve(first_scan, first)
        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        error = json.loads(stderr)
        self.assertEqual("candidate_revision_invalid", error["error"]["code"])

        exit_code, approved, stderr = self._approve(second_scan, second)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("approved", approved["status"])

    def test_approved_disposition_is_refreshed_when_the_manifest_no_longer_matches(
        self,
    ) -> None:
        self._write_json_source("config/runtime.json", "SCAN.REMOVED.SECRET.91c4")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        exit_code, approved, stderr = self._approve(first_scan, first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("approved", approved["status"])

        self.manifest_path.write_text(
            json.dumps({"schema_version": 2, "sources": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        refreshed_scan, _ = self._scan()
        refreshed = self._single_candidate(refreshed_scan)

        self.assertEqual(first["candidate_id"], refreshed["candidate_id"])
        self.assertNotEqual(
            first["candidate_revision"],
            refreshed["candidate_revision"],
        )
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            status = conn.execute("SELECT status FROM protected_source_candidates").fetchone()[0]
        self.assertEqual("proposed", status)

    def test_approved_candidate_is_refreshed_beyond_recent_history_limit(self) -> None:
        self._write_json_source("config/runtime.json", "SCAN.OLD.APPROVED.6be1")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        exit_code, approved, stderr = self._approve(first_scan, first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("approved", approved["status"])
        self.manifest_path.write_text(
            json.dumps({"schema_version": 2, "sources": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        self._bury_candidate_beyond_recent_history(str(first["candidate_id"]))

        refreshed_scan, _ = self._scan()
        refreshed = self._single_candidate(refreshed_scan)

        self.assertEqual(first["candidate_id"], refreshed["candidate_id"])
        self.assertNotEqual(
            first["candidate_revision"],
            refreshed["candidate_revision"],
        )
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            status = conn.execute(
                "SELECT status FROM protected_source_candidates WHERE candidate_id = ?",
                (first["candidate_id"],),
            ).fetchone()[0]
        self.assertEqual("proposed", status)

    def test_stale_detector_proposal_is_rejected_before_any_mutation(self) -> None:
        secret = "SCAN.UPGRADE.PENDING.SECRET.5d10"
        self._write_json_source("config/runtime.json", secret)
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        candidate_id = str(first["candidate_id"])
        self._rewrite_candidate_detector_version(
            candidate_id,
            LEGACY_DETECTOR_VERSION,
        )
        manifest_before = self.manifest_path.read_bytes()
        storage_before = self._candidate_storage_snapshot(candidate_id)

        for action in ("approve", "reject", "ignore"):
            with self.subTest(action=action):
                if action == "approve":
                    exit_code, payload, stderr = self._approve(first_scan, first)
                elif action == "reject":
                    exit_code, payload, stderr = self._reject(first)
                else:
                    exit_code, payload, stderr = self._ignore(first)
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                error = json.loads(stderr)
                self.assertEqual(
                    "candidate_detector_stale",
                    error["error"]["code"],
                )
                self.assertIn("protect scan", error["error"]["message"])
                self.assertNotIn(secret, stderr)
                self.assertEqual(manifest_before, self.manifest_path.read_bytes())
                self.assertEqual(
                    storage_before,
                    self._candidate_storage_snapshot(candidate_id),
                )
        wrong_revision = dict(first)
        wrong_revision["candidate_revision"] = "not-the-saved-revision"
        exit_code, payload, stderr = self._approve(first_scan, wrong_revision)
        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        self.assertEqual(
            "candidate_detector_stale",
            json.loads(stderr)["error"]["code"],
        )
        self.assertEqual(
            storage_before,
            self._candidate_storage_snapshot(candidate_id),
        )
        self.assertNotIn(secret, self._database_text())

        upgraded_scan, _ = self._scan()
        upgraded = self._single_candidate(upgraded_scan)
        self.assertNotEqual(candidate_id, upgraded["candidate_id"])
        repeated_scan, _ = self._scan()
        repeated = self._single_candidate(repeated_scan)
        self.assertEqual(upgraded["candidate_id"], repeated["candidate_id"])
        self.assertNotEqual(
            upgraded["candidate_revision"],
            repeated["candidate_revision"],
        )
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            versions = dict(
                conn.execute(
                    "SELECT candidate_id, detector_version FROM protected_source_candidates"
                ).fetchall()
            )
        self.assertEqual(LEGACY_DETECTOR_VERSION, versions[candidate_id])
        self.assertEqual(
            DETECTOR_VERSION,
            versions[str(upgraded["candidate_id"])],
        )

    def test_legacy_negative_reviews_do_not_suppress_current_detector(self) -> None:
        self._write_json_source("config/a.json", "SCAN.OLD.REJECTED.98a3")
        self._write_json_source("config/z.json", "SCAN.OLD.IGNORED.14b8")
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        exit_code, rejected, stderr = self._reject(first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("rejected", rejected["status"])
        second_scan, _ = self._scan()
        second = self._single_candidate(second_scan)
        exit_code, ignored, stderr = self._ignore(second)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("ignored", ignored["status"])
        self._rewrite_candidate_detector_version(
            str(first["candidate_id"]),
            LEGACY_DETECTOR_VERSION,
        )
        self._rewrite_candidate_detector_version(
            str(second["candidate_id"]),
            LEGACY_DETECTOR_VERSION,
        )

        upgraded_first_scan, _ = self._scan()
        upgraded_first = self._single_candidate(upgraded_first_scan)
        self.assertEqual("config/a.json", upgraded_first["path"])
        self.assertNotEqual(first["candidate_id"], upgraded_first["candidate_id"])
        self.assertEqual(0, upgraded_first_scan["suppressed_count"])
        exit_code, rejected, stderr = self._reject(upgraded_first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("rejected", rejected["status"])

        upgraded_second_scan, _ = self._scan()
        upgraded_second = self._single_candidate(upgraded_second_scan)
        self.assertEqual("config/z.json", upgraded_second["path"])
        self.assertNotEqual(
            second["candidate_id"],
            upgraded_second["candidate_id"],
        )
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            legacy_statuses = dict(
                conn.execute(
                    "SELECT candidate_id, status FROM protected_source_candidates "
                    "WHERE candidate_id IN (?, ?)",
                    (first["candidate_id"], second["candidate_id"]),
                ).fetchall()
            )
        self.assertEqual("rejected", legacy_statuses[str(first["candidate_id"])])
        self.assertEqual("ignored", legacy_statuses[str(second["candidate_id"])])

    def test_unknown_detector_approving_is_rejected_before_release_mutation(
        self,
    ) -> None:
        secret = "SCAN.UPGRADE.UNKNOWN.SECRET.19c4"
        self._write_json_source("config/runtime.json", secret)
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        candidate_id = str(first["candidate_id"])
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            conn.execute(
                """
                UPDATE protected_source_candidates
                SET status = 'approving',
                    approval_attempt_id = ?,
                    approval_started_at = CURRENT_TIMESTAMP
                WHERE candidate_id = ?
                """,
                ("d" * 32, candidate_id),
            )
        self._rewrite_candidate_detector_version(
            candidate_id,
            "protected-source-candidate-v999",
        )
        manifest_before = self.manifest_path.read_bytes()
        storage_before = self._candidate_storage_snapshot(candidate_id)

        for action in ("approve", "reject", "ignore"):
            with self.subTest(action=action):
                if action == "approve":
                    exit_code, payload, stderr = self._approve(first_scan, first)
                elif action == "reject":
                    exit_code, payload, stderr = self._reject(first)
                else:
                    exit_code, payload, stderr = self._ignore(first)
                self.assertEqual(1, exit_code)
                self.assertEqual({}, payload)
                self.assertEqual(
                    "candidate_detector_stale",
                    json.loads(stderr)["error"]["code"],
                )
                self.assertNotIn(secret, stderr)
                self.assertEqual(manifest_before, self.manifest_path.read_bytes())
                self.assertEqual(
                    storage_before,
                    self._candidate_storage_snapshot(candidate_id),
                )
        self.assertNotIn(secret, self._database_text())

    def test_legacy_approved_candidate_keeps_manifest_and_runtime_active(self) -> None:
        secret = "SCAN.UPGRADE.APPROVED.SECRET.7cb2"
        self._write_json_source("config/runtime.json", secret)
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        exit_code, approved, stderr = self._approve(first_scan, first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("approved", approved["status"])
        manifest_before = self.manifest_path.read_bytes()
        self._rewrite_candidate_detector_version(
            str(first["candidate_id"]),
            LEGACY_DETECTOR_VERSION,
        )
        approved_storage = self._candidate_storage_snapshot(str(first["candidate_id"]))

        exit_code, recovered, stderr = self._approve(first_scan, first)
        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("already_registered", recovered["status"])
        self.assertEqual(
            approved_storage,
            self._candidate_storage_snapshot(str(first["candidate_id"])),
        )
        self.assertNotIn(secret, json.dumps(recovered) + stderr)

        repeated_scan, stderr = self._scan()

        self.assertEqual("no_candidate", repeated_scan["status"])
        self.assertGreaterEqual(repeated_scan["already_registered_count"], 1)
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        self.assertNotIn(secret, json.dumps(repeated_scan) + stderr)
        for command, expected_status in (("doctor", "ok"), ("status", "active")):
            with self.subTest(command=command):
                exit_code, payload, stderr = self._run_json(
                    command,
                    "--workspace",
                    str(self.workspace),
                    "--data-dir",
                    str(self.data_dir),
                    "--json",
                )
                self.assertEqual(0, exit_code, stderr)
                self.assertEqual(expected_status, payload["status"])
                self.assertNotIn(secret, json.dumps(payload) + stderr)

    def test_legacy_approving_candidate_can_finish_exact_recovery(self) -> None:
        secret = "SCAN.UPGRADE.APPROVING.SECRET.6e91"
        self._write_json_source("config/runtime.json", secret)
        first_scan, _ = self._scan()
        first = self._single_candidate(first_scan)
        installed_manifest = {
            "schema_version": 2,
            "sources": [first["proposed_source"]],
        }
        self.manifest_path.write_text(
            json.dumps(installed_manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        approval_attempt_id = "a" * 32
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            conn.execute(
                """
                UPDATE protected_source_candidates
                SET status = 'approving',
                    approval_attempt_id = ?,
                    approval_started_at = CURRENT_TIMESTAMP
                WHERE candidate_id = ?
                """,
                (approval_attempt_id, first["candidate_id"]),
            )
        self._rewrite_candidate_detector_version(
            str(first["candidate_id"]),
            LEGACY_DETECTOR_VERSION,
        )
        manifest_before = self.manifest_path.read_bytes()

        exit_code, recovered, stderr = self._approve(first_scan, first)

        self.assertEqual(0, exit_code, stderr)
        self.assertEqual("already_registered", recovered["status"])
        self.assertEqual(manifest_before, self.manifest_path.read_bytes())
        self.assertNotIn(secret, json.dumps(recovered) + stderr)
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            stored = conn.execute(
                """
                SELECT detector_version, status, approval_attempt_id
                FROM protected_source_candidates
                WHERE candidate_id = ?
                """,
                (first["candidate_id"],),
            ).fetchone()
            decision = conn.execute(
                """
                SELECT decision_code
                FROM protected_source_candidate_reviews
                WHERE candidate_id = ?
                ORDER BY rowid DESC LIMIT 1
                """,
                (first["candidate_id"],),
            ).fetchone()[0]
        self.assertEqual(
            (LEGACY_DETECTOR_VERSION, "approved", None),
            stored,
        )
        self.assertEqual("already_registered", decision)

    def test_legacy_manifest_stops_before_candidate_storage(self) -> None:
        secret = "SCAN.LEGACY.SECRET.40c1"
        self._write_json_source("config/runtime.json", secret)
        self.manifest_path.write_text(
            json.dumps({"schema_version": 1, "sources": []}),
            encoding="utf-8",
        )

        exit_code, payload, stderr = self._run_json(*self._protect_arguments("scan"))

        self.assertEqual(1, exit_code)
        self.assertEqual({}, payload)
        error = json.loads(stderr)
        self.assertEqual("manifest_schema_legacy", error["error"]["code"])
        self.assertNotIn(secret, stderr)
        with sqlite3.connect(self.data_dir / "events.db") as conn:
            count = conn.execute("SELECT COUNT(*) FROM protected_source_candidates").fetchone()[0]
        self.assertEqual(0, count)

    def test_partial_scan_without_a_candidate_never_reports_no_candidate(self) -> None:
        manifest_sha256 = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        incomplete = SimpleNamespace(
            scanner_version="protected-source-scan-v1",
            manifest_sha256=manifest_sha256,
            scan_complete=False,
            truncation_reasons=("entry_limit",),
            candidates=(),
            already_registered_count=0,
            entries_seen=20_000,
            directories_scanned=12,
            files_seen=100,
            eligible_files_seen=4,
            inspected_bytes=1024,
            detected_candidate_count=0,
            public_candidate_bytes=0,
            skipped_counts=(("entry_limit", 1),),
        )
        with patch("tooluseproxy.cli.scan_protected_sources", return_value=incomplete):
            payload, stderr = self._scan()

        self.assertEqual("", stderr)
        self.assertEqual("scan_incomplete", payload["status"])
        self.assertFalse(payload["scan_complete"])
        self.assertEqual(["entry_limit"], payload["truncation_reasons"])
        self.assertEqual({"entry_limit": 1}, payload["skipped_counts"])
        self.assertEqual([], payload["candidates"])
        self.assertTrue(payload["continuation_required"])

    def test_text_output_is_value_free_and_includes_scan_control_fields(self) -> None:
        secret = "SCAN.TEXT.SECRET.19de"
        self._write_json_source("config/runtime.json", secret)
        exit_code, stdout, stderr = self._run_raw(
            "protect",
            "scan",
            "--workspace",
            str(self.workspace),
            "--data-dir",
            str(self.data_dir),
        )

        self.assertEqual(0, exit_code, stderr)
        self.assertIn("status: review_required", stdout)
        self.assertIn("scan_complete: True", stdout)
        self.assertIn("approval_mode: batch", stdout)
        self.assertIn("review_batch_limit: 10", stdout)
        self.assertIn("remaining_candidate_count: 0", stdout)
        self.assertIn('"path": "config/runtime.json"', stdout)
        self.assertNotIn(secret, stdout + stderr)
        self.assertNotIn(str(self.workspace.resolve()), stdout + stderr)

    def test_data_directory_exclusions_are_workspace_relative(self) -> None:
        inside = self.workspace / "state"
        outside = self.workspace.parent / "outside-state"
        self.assertEqual(
            ("state",),
            _scan_excluded_relative_paths(
                self.workspace,
                RuntimePaths(inside, inside / "events.db", "test"),
            ),
        )

        workspace_alias = self.workspace.parent / "workspace-alias"
        workspace_alias.symlink_to(self.workspace, target_is_directory=True)
        self.assertEqual(
            ("state",),
            _scan_excluded_relative_paths(
                self.workspace.resolve(),
                RuntimePaths(
                    workspace_alias / "state",
                    workspace_alias / "state" / "events.db",
                    "test",
                ),
            ),
        )
        self.assertEqual(
            (
                ".tooluseproxy-data.json",
                "events.db",
                "events.db-shm",
                "events.db-wal",
                "manifest-backups",
            ),
            _scan_excluded_relative_paths(
                self.workspace,
                RuntimePaths(
                    self.workspace,
                    self.workspace / "events.db",
                    "test",
                ),
            ),
        )
        self.assertEqual(
            (),
            _scan_excluded_relative_paths(
                self.workspace,
                RuntimePaths(outside, outside / "events.db", "test"),
            ),
        )

    def test_data_directory_case_alias_excludes_the_same_filesystem_object(self) -> None:
        actual_data_dir = self.workspace / "state"
        backup_dir = actual_data_dir / "manifest-backups"
        backup_dir.mkdir(parents=True)
        backup = backup_dir / "legacy.json"
        backup.write_text(
            json.dumps({"private_token": "CASE.ALIAS.RUNTIME.SECRET.7c31"}),
            encoding="utf-8",
        )
        workspace_alias = self.workspace.parent / self.workspace.name.upper()
        case_alias = workspace_alias / "STATE"
        if not case_alias.exists():
            self.skipTest("case-sensitive filesystem has no case alias")

        exclusions = _scan_excluded_relative_paths(
            self.workspace,
            RuntimePaths(case_alias, case_alias / "events.db", "test"),
        )
        result = scan_protected_sources(
            self.workspace,
            "case-alias-exclusion-workspace",
            excluded_relative_paths=exclusions,
        )

        self.assertEqual(("STATE",), exclusions)
        self.assertEqual((), result.candidates)
        self.assertEqual(1, dict(result.skipped_counts)["excluded_path"])

    def test_workspace_case_alias_still_excludes_root_runtime_data(self) -> None:
        workspace_alias = self.workspace.parent / self.workspace.name.upper()
        if not workspace_alias.exists():
            self.skipTest("case-sensitive filesystem has no case alias")
        backup_dir = self.workspace / "manifest-backups"
        backup_dir.mkdir()
        (backup_dir / "legacy.json").write_text(
            json.dumps({"private_token": "ROOT.CASE.ALIAS.SECRET.4b12"}),
            encoding="utf-8",
        )
        (self.workspace / "events.db").write_text("runtime state", encoding="utf-8")

        exclusions = _scan_excluded_relative_paths(
            self.workspace,
            RuntimePaths(
                workspace_alias,
                workspace_alias / "events.db",
                "test",
            ),
        )
        result = scan_protected_sources(
            self.workspace,
            "root-case-alias-exclusion-workspace",
            excluded_relative_paths=exclusions,
        )

        self.assertEqual(
            (
                ".tooluseproxy-data.json",
                "events.db",
                "events.db-shm",
                "events.db-wal",
                "manifest-backups",
            ),
            exclusions,
        )
        self.assertEqual((), result.candidates)
        self.assertEqual(2, dict(result.skipped_counts)["excluded_path"])

    def test_scan_has_no_path_approval_or_limit_override_options(self) -> None:
        for forbidden in (
            ("--path", "config/runtime.json"),
            ("--yes",),
            ("--approve",),
            ("--max-files", "20000"),
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(SystemExit) as raised:
                    self._run_raw("protect", "scan", *forbidden)
                self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
