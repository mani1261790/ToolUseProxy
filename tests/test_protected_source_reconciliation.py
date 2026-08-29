from __future__ import annotations

import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from tooluseproxy.cli import main as tooluseproxy_main
from tooluseproxy.protected_sources import (
    ProtectedSourceRegistrationError,
    apply_unavailable_source_reconciliation,
    plan_unavailable_source_reconciliation,
)


class ProtectedSourceReconciliationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workspace"
        self.backup_root = Path(self.temporary.name) / "plugin-data"
        self.root.mkdir(mode=0o700)
        self.backup_root.mkdir(mode=0o700)
        (self.root / "available.md").write_text(
            "PRIVATE_RECONCILIATION_CANARY",
            encoding="utf-8",
        )
        self.manifest_path = self.root / "protected_sources.json"
        self.manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "project_note": "preserve-me",
                    "sources": [
                        {
                            "id": "available",
                            "path": "available.md",
                            "type": "secretfile",
                            "sensitivity": "high",
                            "policy_tags": ["no_external"],
                        },
                        {
                            "id": "missing",
                            "path": "moved/missing.md",
                            "type": "secretfile",
                            "sensitivity": "high",
                            "policy_tags": ["no_external"],
                        },
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_plan_is_value_free_and_apply_is_atomic_and_idempotent(self) -> None:
        original_manifest = self.manifest_path.read_bytes()
        plan = plan_unavailable_source_reconciliation(
            self.root,
            workspace_id="workspace-test",
            backup_root=self.backup_root,
        )

        self.assertEqual("review_required", plan.status)
        self.assertEqual((("missing", "moved/missing.md"),), plan.unavailable_sources)
        self.assertEqual(1, plan.remaining_source_count)
        self.assertIsNone(plan.encoded_manifest)
        public = json.dumps(plan.to_public_payload(), ensure_ascii=False)
        self.assertNotIn("PRIVATE_RECONCILIATION_CANARY", public)
        assert plan.reconciliation_revision is not None

        result = apply_unavailable_source_reconciliation(
            self.root,
            workspace_id="workspace-test",
            reconciliation_revision=plan.reconciliation_revision,
            expected_manifest_sha256=plan.manifest_sha256,
            backup_root=self.backup_root,
        )

        self.assertEqual("reconciled", result.status)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual("preserve-me", manifest["project_note"])
        self.assertEqual(["available"], [item["id"] for item in manifest["sources"]])
        self.assertEqual(
            "PRIVATE_RECONCILIATION_CANARY",
            (self.root / "available.md").read_text(encoding="utf-8"),
        )
        backup = self.backup_root / result.backup_relative_path
        self.assertEqual(original_manifest, backup.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))

        repeated = apply_unavailable_source_reconciliation(
            self.root,
            workspace_id="workspace-test",
            reconciliation_revision=plan.reconciliation_revision,
            expected_manifest_sha256=plan.manifest_sha256,
            backup_root=self.backup_root,
        )
        self.assertEqual("already_reconciled", repeated.status)

    def test_changed_manifest_rejects_reviewed_plan(self) -> None:
        plan = plan_unavailable_source_reconciliation(
            self.root,
            workspace_id="workspace-test",
            backup_root=self.backup_root,
        )
        assert plan.reconciliation_revision is not None
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        payload["project_note"] = "changed"
        self.manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ProtectedSourceRegistrationError) as caught:
            apply_unavailable_source_reconciliation(
                self.root,
                workspace_id="workspace-test",
                reconciliation_revision=plan.reconciliation_revision,
                expected_manifest_sha256=plan.manifest_sha256,
                backup_root=self.backup_root,
            )

        self.assertEqual("manifest_reconciliation_conflict", caught.exception.code)

    def test_apply_rejects_non_string_commitments_with_stable_codes(self) -> None:
        with self.assertRaises(ProtectedSourceRegistrationError) as revision_error:
            apply_unavailable_source_reconciliation(
                self.root,
                workspace_id="workspace-test",
                reconciliation_revision=1,  # type: ignore[arg-type]
                expected_manifest_sha256="a" * 64,
                backup_root=self.backup_root,
            )
        self.assertEqual(
            "manifest_reconciliation_revision_invalid",
            revision_error.exception.code,
        )

        with self.assertRaises(ProtectedSourceRegistrationError) as hash_error:
            apply_unavailable_source_reconciliation(
                self.root,
                workspace_id="workspace-test",
                reconciliation_revision="r1_" + "a" * 64,
                expected_manifest_sha256=1,  # type: ignore[arg-type]
                backup_root=self.backup_root,
            )
        self.assertEqual("manifest_reconciliation_conflict", hash_error.exception.code)

    def test_clean_manifest_requires_no_review(self) -> None:
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        payload["sources"] = payload["sources"][:1]
        self.manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        plan = plan_unavailable_source_reconciliation(
            self.root,
            workspace_id="workspace-test",
            backup_root=self.backup_root,
        )

        self.assertEqual("clean", plan.status)
        self.assertFalse(plan.to_public_payload()["review_required"])

    def test_cli_plan_and_apply_use_the_reviewed_revision(self) -> None:
        db_path = self.backup_root / "events.db"
        store = EventStore(db_path)
        store.initialize()
        workspace = resolve_workspace(
            str(self.root),
            str(self.root),
            discovered_by="test",
        )
        store.register_workspace(workspace)
        plan_stdout = StringIO()
        with redirect_stdout(plan_stdout):
            plan_exit = tooluseproxy_main(
                [
                    "protect",
                    "reconcile",
                    "plan",
                    "--workspace",
                    str(self.root),
                    "--db",
                    str(db_path),
                    "--json",
                ]
            )
        self.assertEqual(0, plan_exit)
        plan = json.loads(plan_stdout.getvalue())

        apply_stdout = StringIO()
        with redirect_stdout(apply_stdout):
            apply_exit = tooluseproxy_main(
                [
                    "protect",
                    "reconcile",
                    "apply",
                    "--reconciliation-revision",
                    plan["reconciliation_revision"],
                    "--expected-manifest-sha256",
                    plan["manifest_sha256"],
                    "--workspace",
                    str(self.root),
                    "--db",
                    str(db_path),
                    "--json",
                ]
            )
        self.assertEqual(0, apply_exit)
        applied = json.loads(apply_stdout.getvalue())
        self.assertEqual("reconciled", applied["status"])

    def test_cli_text_plan_includes_paths_and_apply_commitments(self) -> None:
        db_path = self.backup_root / "events.db"
        store = EventStore(db_path)
        store.initialize()
        workspace = resolve_workspace(
            str(self.root),
            str(self.root),
            discovered_by="test",
        )
        store.register_workspace(workspace)
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = tooluseproxy_main(
                [
                    "protect",
                    "reconcile",
                    "plan",
                    "--workspace",
                    str(self.root),
                    "--db",
                    str(db_path),
                ]
            )

        self.assertEqual(0, exit_code)
        rendered = stdout.getvalue()
        self.assertIn("reconciliation_revision: r1_", rendered)
        self.assertIn("moved/missing.md", rendered)
        self.assertIn("unavailable_source_count: 1", rendered)

    def test_setup_reports_reconciliation_instead_of_generic_failure(self) -> None:
        db_path = self.backup_root / "events.db"
        store = EventStore(db_path)
        store.initialize()
        workspace = resolve_workspace(
            str(self.root),
            str(self.root),
            discovered_by="test",
        )
        store.register_workspace(workspace)

        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = tooluseproxy_main(
                [
                    "setup",
                    "apply",
                    "file-payload-exact",
                    "--codex",
                    "--expect-compatible-settings",
                    "--workspace",
                    str(self.root),
                    "--db",
                    str(db_path),
                    "--json",
                ]
            )

        self.assertEqual(1, exit_code)
        payload = json.loads(stderr.getvalue())
        self.assertEqual("protected_source_unavailable", payload["error"]["code"])
        assert workspace.workspace_id is not None
        settings = store.get_workspace_runtime_settings(workspace.workspace_id)
        self.assertEqual({}, settings.settings)


if __name__ == "__main__":
    unittest.main()
