from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hook_monitor.runtime.models import ProtectedSourceCandidate
from hook_monitor.runtime.storage import (
    CURRENT_SCHEMA_VERSION,
    EventStore,
    ProtectedSourceCandidateStateError,
    SchemaCompatibilityError,
)
from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy.cli import main as cli_main
from tooluseproxy.protected_sources import suggest_protected_source


class ProtectedSourceCandidateStorageTest(unittest.TestCase):
    def test_bounded_exact_suppression_fingerprint_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))
            missing_fingerprint = hashlib.sha256(b"missing candidate").hexdigest()

            found = (
                store.list_protected_source_candidates_by_suppression_fingerprints(
                    candidate.workspace_id,
                    (missing_fingerprint, candidate.suppression_fingerprint),
                )
            )

            self.assertEqual([candidate.candidate_id], [item.candidate_id for item in found])
            self.assertEqual(
                [],
                store.list_protected_source_candidates_by_suppression_fingerprints(
                    candidate.workspace_id,
                    (),
                ),
            )
            invalid_inputs = (
                [candidate.suppression_fingerprint],
                ("not-a-sha256",),
                (
                    candidate.suppression_fingerprint,
                    candidate.suppression_fingerprint,
                ),
                tuple(
                    hashlib.sha256(f"candidate-{index}".encode()).hexdigest()
                    for index in range(65)
                ),
            )
            for fingerprints in invalid_inputs:
                with self.subTest(fingerprints_type=type(fingerprints).__name__):
                    with self.assertRaises(ValueError):
                        store.list_protected_source_candidates_by_suppression_fingerprints(
                            candidate.workspace_id,
                            fingerprints,  # type: ignore[arg-type]
                        )

    def test_claim_then_finalize_records_one_approval_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))

            claimed = store.claim_protected_source_candidate_approval(
                candidate.candidate_id,
                expected_revision_sha256=candidate.candidate_revision_sha256,
                expected_manifest_sha256=candidate.manifest_sha256,
            )

            self.assertEqual("approving", claimed.status)
            self.assertRegex(claimed.approval_attempt_id or "", r"[0-9a-f]{32}\Z")
            self.assertIsNotNone(claimed.approval_started_at)
            result_manifest_sha256 = hashlib.sha256(b"updated manifest").hexdigest()
            approved_source_id = json.loads(candidate.proposed_source_json)["id"]

            approved = store.finalize_protected_source_candidate_approval(
                claimed.candidate_id,
                approval_attempt_id=claimed.approval_attempt_id or "",
                expected_revision_sha256=claimed.candidate_revision_sha256,
                expected_manifest_sha256=claimed.manifest_sha256,
                result_manifest_sha256=result_manifest_sha256,
                approved_source_id=approved_source_id,
                decision_code="approved",
            )

            self.assertEqual("approved", approved.status)
            self.assertEqual(result_manifest_sha256, approved.manifest_sha256)
            self.assertEqual(approved_source_id, approved.approved_source_id)
            self.assertIsNone(approved.approval_attempt_id)
            self.assertIsNone(approved.approval_started_at)
            reviews = store.list_protected_source_candidate_reviews(
                candidate.candidate_id
            )
            self.assertEqual(
                ["proposed", "approval_started", "approved"],
                [review.decision_code for review in reviews],
            )
            self.assertEqual(
                claimed.approval_attempt_id,
                reviews[-1].approval_attempt_id,
            )

    def test_claim_release_returns_to_proposed_or_marks_stale(self) -> None:
        cases = (
            ("approval_released", "proposed", True),
            ("manifest_changed", "stale", False),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for decision_code, expected_status, report_expected_manifest in cases:
                with self.subTest(decision_code=decision_code):
                    store, candidate = self._candidate(root / decision_code)
                    claimed = store.claim_protected_source_candidate_approval(
                        candidate.candidate_id,
                        expected_revision_sha256=(
                            candidate.candidate_revision_sha256
                        ),
                        expected_manifest_sha256=candidate.manifest_sha256,
                    )

                    released = store.release_protected_source_candidate_approval(
                        claimed.candidate_id,
                        approval_attempt_id=claimed.approval_attempt_id or "",
                        expected_revision_sha256=(
                            claimed.candidate_revision_sha256
                        ),
                        expected_manifest_sha256=claimed.manifest_sha256,
                        result_manifest_sha256=(
                            claimed.manifest_sha256
                            if report_expected_manifest
                            else None
                        ),
                        decision_code=decision_code,
                    )

                    self.assertEqual(expected_status, released.status)
                    self.assertEqual(
                        claimed.manifest_sha256,
                        released.manifest_sha256,
                    )
                    self.assertIsNone(released.approval_attempt_id)
                    self.assertIsNone(released.approval_started_at)
                    self.assertEqual(
                        decision_code,
                        store.list_protected_source_candidate_reviews(
                            candidate.candidate_id
                        )[-1].decision_code,
                    )

    def test_reject_loses_compare_and_swap_after_approval_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))
            claimed = store.claim_protected_source_candidate_approval(
                candidate.candidate_id,
                expected_revision_sha256=candidate.candidate_revision_sha256,
                expected_manifest_sha256=candidate.manifest_sha256,
            )

            with self.assertRaises(ProtectedSourceCandidateStateError) as raised:
                store.transition_protected_source_candidate(
                    candidate.candidate_id,
                    expected_status="proposed",
                    expected_revision_sha256=(
                        candidate.candidate_revision_sha256
                    ),
                    to_status="rejected",
                    decision_code="rejected",
                    authority="cli_explicit",
                    expected_manifest_sha256=candidate.manifest_sha256,
                    result_manifest_sha256=candidate.manifest_sha256,
                )

            self.assertEqual("candidate_state_conflict", raised.exception.code)
            self.assertEqual(
                claimed,
                store.get_protected_source_candidate(candidate.candidate_id),
            )

    def test_stale_candidate_cannot_be_approved_by_legacy_reconcile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))
            stale = store.transition_protected_source_candidate(
                candidate.candidate_id,
                expected_status="proposed",
                expected_revision_sha256=candidate.candidate_revision_sha256,
                to_status="stale",
                decision_code="source_changed",
                authority="cli_explicit",
                expected_manifest_sha256=candidate.manifest_sha256,
                result_manifest_sha256=candidate.manifest_sha256,
            )

            with self.assertRaises(ProtectedSourceCandidateStateError) as raised:
                store.reconcile_protected_source_candidate(
                    stale.candidate_id,
                    expected_status="stale",
                    approval_attempt_id="a" * 32,
                    expected_revision_sha256=stale.candidate_revision_sha256,
                    decision_code="approved",
                    authority="system_reconcile",
                    expected_manifest_sha256=stale.manifest_sha256,
                    result_manifest_sha256="5" * 64,
                    approved_source_id="stale-source",
                )

            self.assertEqual("candidate_state_conflict", raised.exception.code)
            approved_source_id = json.loads(stale.proposed_source_json)["id"]
            selected = (
                store.select_registered_protected_source_candidate_for_reconcile(
                    stale.workspace_id,
                    stale.suppression_fingerprint,
                    proposed_source_json=stale.proposed_source_json,
                    approved_source_id=approved_source_id,
                )
            )
            self.assertEqual(stale, selected)
            unchanged = store.reconcile_registered_protected_source_candidate(
                stale.candidate_id,
                stale.workspace_id,
                stale.suppression_fingerprint,
                approval_attempt_id=None,
                proposed_source_json=stale.proposed_source_json,
                result_manifest_sha256="5" * 64,
                approved_source_id=approved_source_id,
            )
            self.assertEqual(stale, unchanged)

    def test_registered_reconcile_requires_the_exact_proposed_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))
            claimed = store.claim_protected_source_candidate_approval(
                candidate.candidate_id,
                expected_revision_sha256=candidate.candidate_revision_sha256,
                expected_manifest_sha256=candidate.manifest_sha256,
            )
            mismatched_source = json.loads(claimed.proposed_source_json)
            mismatched_source["selector"] = {"dotenv_keys": ["OTHER_PASSWORD"]}
            mismatched_source_json = json.dumps(
                mismatched_source,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

            selected = (
                store.select_registered_protected_source_candidate_for_reconcile(
                    claimed.workspace_id,
                    claimed.suppression_fingerprint,
                    proposed_source_json=mismatched_source_json,
                    approved_source_id=mismatched_source["id"],
                )
            )
            self.assertIsNone(selected)
            with self.assertRaises(ProtectedSourceCandidateStateError) as raised:
                store.reconcile_registered_protected_source_candidate(
                    claimed.candidate_id,
                    claimed.workspace_id,
                    claimed.suppression_fingerprint,
                    approval_attempt_id=claimed.approval_attempt_id,
                    proposed_source_json=mismatched_source_json,
                    result_manifest_sha256="5" * 64,
                    approved_source_id=mismatched_source["id"],
                )

            self.assertEqual(
                "registered_reconcile_identity_conflict",
                raised.exception.code,
            )
            unchanged = store.get_protected_source_candidate(claimed.candidate_id)
            self.assertEqual(claimed, unchanged)
            self.assertEqual(
                "approving",
                store.get_protected_source_candidate(claimed.candidate_id).status,
            )
            self.assertNotIn(
                "reconciled_approved",
                [
                    review.decision_code
                    for review in store.list_protected_source_candidate_reviews(
                        claimed.candidate_id
                    )
                ],
            )

    def test_registered_reconcile_refuses_multiple_matching_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store, first = self._candidate(root)
            first = store.claim_protected_source_candidate_approval(
                first.candidate_id,
                expected_revision_sha256=first.candidate_revision_sha256,
                expected_manifest_sha256=first.manifest_sha256,
            )
            source_path = root / "workspace" / ".env.candidate"
            source_path.write_text(
                "PRIVATE_TOKEN=rotated-candidate-storage-secret\nPUBLIC_MODE=test\n",
                encoding="utf-8",
            )
            proposal = suggest_protected_source(
                root / "workspace",
                source_path.name,
                workspace_id=first.workspace_id,
            )
            second = store.create_or_get_protected_source_candidate(
                **proposal.to_storage_record()
            ).candidate
            second = store.claim_protected_source_candidate_approval(
                second.candidate_id,
                expected_revision_sha256=second.candidate_revision_sha256,
                expected_manifest_sha256=second.manifest_sha256,
            )
            self.assertEqual(first.proposed_source_json, second.proposed_source_json)
            self.assertNotEqual(first.suppression_fingerprint, second.suppression_fingerprint)
            approved_source_id = json.loads(second.proposed_source_json)["id"]

            with self.assertRaises(ProtectedSourceCandidateStateError) as raised:
                store.select_registered_protected_source_candidate_for_reconcile(
                    second.workspace_id,
                    second.suppression_fingerprint,
                    proposed_source_json=second.proposed_source_json,
                    approved_source_id=approved_source_id,
                )

            self.assertEqual("registered_reconcile_ambiguous", raised.exception.code)
            self.assertEqual(
                ["approving", "approving"],
                [
                    store.get_protected_source_candidate(candidate.candidate_id).status
                    for candidate in (first, second)
                ],
            )

    def test_review_history_is_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))
            review = store.list_protected_source_candidate_reviews(
                candidate.candidate_id
            )[0]

            statements = (
                "UPDATE protected_source_candidate_reviews "
                "SET authority = 'system_reconcile' WHERE review_id = ?",
                "DELETE FROM protected_source_candidate_reviews WHERE review_id = ?",
            )
            for statement in statements:
                with self.subTest(statement=statement.split()[0]):
                    with sqlite3.connect(store.db_path) as connection:
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(statement, (review.review_id,))

            self.assertEqual(
                [review],
                store.list_protected_source_candidate_reviews(
                    candidate.candidate_id
                ),
            )

    def test_approving_invariant_is_enforced_by_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store, candidate = self._candidate(Path(temporary_directory))

            statements = (
                (
                    "UPDATE protected_source_candidates "
                    "SET status = 'approving' WHERE candidate_id = ?",
                    (candidate.candidate_id,),
                ),
                (
                    "UPDATE protected_source_candidates "
                    "SET approval_attempt_id = ?, approval_started_at = 'now' "
                    "WHERE candidate_id = ?",
                    ("a" * 32, candidate.candidate_id),
                ),
            )
            for statement, parameters in statements:
                with self.subTest(statement=statement):
                    with sqlite3.connect(store.db_path) as connection:
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(statement, parameters)

    def test_init_backs_up_and_repairs_missing_candidate_schema_objects(
        self,
    ) -> None:
        objects = (
            (
                "TRIGGER",
                "protected_source_candidate_reviews_no_update",
            ),
            (
                "TRIGGER",
                "protected_source_candidate_reviews_no_delete",
            ),
            (
                "INDEX",
                "idx_protected_source_candidates_workspace_suppression",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for object_type, object_name in objects:
                with self.subTest(object_name=object_name):
                    case_root = root / object_name
                    workspace = case_root / "workspace"
                    data_dir = case_root / "data"
                    workspace.mkdir(parents=True)
                    store = EventStore(data_dir / "events.db")
                    store.initialize()
                    with sqlite3.connect(store.db_path) as connection:
                        connection.execute(
                            "CREATE TABLE repair_marker (value TEXT NOT NULL)"
                        )
                        connection.execute(
                            "INSERT INTO repair_marker VALUES ('before-repair')"
                        )
                        connection.execute(f"DROP {object_type} {object_name}")
                        self.assertEqual(
                            CURRENT_SCHEMA_VERSION,
                            connection.execute("PRAGMA user_version").fetchone()[0],
                        )

                    with self.assertRaises(SchemaCompatibilityError) as raised:
                        store.require_runtime_schema()
                    self.assertEqual("schema_incomplete", raised.exception.code)
                    self.assertIn(object_name, str(raised.exception))

                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
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

                    self.assertEqual(0, exit_code)
                    backup_path = Path(
                        json.loads(stdout.getvalue())["migration_backup"]
                    )
                    self.assertTrue(backup_path.is_file())
                    with sqlite3.connect(backup_path) as connection:
                        self.assertEqual(
                            ("before-repair",),
                            connection.execute(
                                "SELECT value FROM repair_marker"
                            ).fetchone(),
                        )
                        self.assertIsNone(
                            connection.execute(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = ? AND name = ?",
                                (object_type.lower(), object_name),
                            ).fetchone()
                        )

                    store.require_runtime_schema()
                    with sqlite3.connect(store.db_path) as connection:
                        self.assertEqual(
                            (object_name,),
                            connection.execute(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = ? AND name = ?",
                                (object_type.lower(), object_name),
                            ).fetchone(),
                        )

    @staticmethod
    def _candidate(root: Path) -> tuple[EventStore, ProtectedSourceCandidate]:
        workspace = root / "workspace"
        workspace.mkdir(parents=True)
        store = EventStore(root / "events.db")
        store.initialize()
        context = resolve_workspace(
            str(workspace),
            str(workspace),
            discovered_by="candidate-storage-test",
        )
        if not context.ready or context.workspace_id is None:
            raise AssertionError("fixture workspace must resolve")
        store.register_workspace(context)

        manifest_path = workspace / "protected_sources.json"
        manifest_path.write_text(
            '{"schema_version":2,"sources":[]}\n',
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        source_path = workspace / ".env.candidate"
        source_path.write_text(
            "PRIVATE_TOKEN=candidate-storage-secret\nPUBLIC_MODE=test\n",
            encoding="utf-8",
        )
        source_path.chmod(0o600)
        proposal = suggest_protected_source(
            workspace,
            source_path.name,
            workspace_id=context.workspace_id,
        )
        created = store.create_or_get_protected_source_candidate(
            **proposal.to_storage_record()
        )
        if not created.created:
            raise AssertionError("fixture candidate must be created")
        return store, created.candidate


if __name__ == "__main__":
    unittest.main()
