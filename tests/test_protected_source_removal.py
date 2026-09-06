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
    apply_protected_source_removal,
    plan_protected_source_removal,
)


class ProtectedSourceRemovalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workspace"
        self.backup_root = Path(self.temporary.name) / "plugin-data"
        self.root.mkdir(mode=0o700)
        self.backup_root.mkdir(mode=0o700)
        (self.root / "README.md").write_text("PRIVATE_CANARY", encoding="utf-8")
        (self.root / "keep.md").write_text("KEEP_CANARY", encoding="utf-8")
        self.manifest_path = self.root / "protected_sources.json"
        self.manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "project_note": "preserve-me",
                    "sources": [
                        {
                            "id": "readme",
                            "path": "README.md",
                            "type": "secretfile",
                            "sensitivity": "high",
                            "policy_tags": ["no_external"],
                        },
                        {
                            "id": "keep",
                            "path": "keep.md",
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

    def test_plan_and_apply_remove_only_registration_and_are_idempotent(self) -> None:
        original_manifest = self.manifest_path.read_bytes()
        plan = plan_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            backup_root=self.backup_root,
        )

        self.assertEqual("README.md", plan.relative_path)
        self.assertEqual("readme", plan.source_id)
        self.assertEqual(1, plan.remaining_source_count)
        self.assertIsNone(plan.encoded_manifest)
        public = json.dumps(plan.to_public_payload(), ensure_ascii=False)
        self.assertNotIn("PRIVATE_CANARY", public)

        result = apply_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            removal_revision=plan.removal_revision,
            expected_manifest_sha256=plan.manifest_sha256,
            backup_root=self.backup_root,
        )

        self.assertEqual("removed", result.status)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual("preserve-me", manifest["project_note"])
        self.assertEqual(["keep"], [item["id"] for item in manifest["sources"]])
        self.assertEqual("PRIVATE_CANARY", (self.root / "README.md").read_text())
        self.assertEqual("KEEP_CANARY", (self.root / "keep.md").read_text())
        backup = self.backup_root / result.backup_relative_path
        self.assertEqual(original_manifest, backup.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))

        repeated = apply_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            removal_revision=plan.removal_revision,
            expected_manifest_sha256=plan.manifest_sha256,
            backup_root=self.backup_root,
        )
        self.assertEqual("already_removed", repeated.status)

    def test_changed_manifest_and_wrong_target_are_rejected(self) -> None:
        plan = plan_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            backup_root=self.backup_root,
        )
        with self.assertRaises(ProtectedSourceRegistrationError) as wrong_target:
            apply_protected_source_removal(
                self.root,
                workspace_id="workspace-test",
                relative_path="keep.md",
                removal_revision=plan.removal_revision,
                expected_manifest_sha256=plan.manifest_sha256,
                backup_root=self.backup_root,
            )
        self.assertEqual(
            "manifest_removal_revision_invalid",
            wrong_target.exception.code,
        )
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        payload["project_note"] = "changed"
        self.manifest_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with self.assertRaises(ProtectedSourceRegistrationError) as caught:
            apply_protected_source_removal(
                self.root,
                workspace_id="workspace-test",
                relative_path="README.md",
                removal_revision=plan.removal_revision,
                expected_manifest_sha256=plan.manifest_sha256,
                backup_root=self.backup_root,
            )
        self.assertEqual("manifest_removal_conflict", caught.exception.code)

        with self.assertRaises(ProtectedSourceRegistrationError) as missing:
            plan_protected_source_removal(
                self.root,
                workspace_id="workspace-test",
                relative_path="missing.md",
                backup_root=self.backup_root,
            )
        self.assertEqual("manifest_removal_source_missing", missing.exception.code)

    def test_missing_source_file_can_still_be_unregistered(self) -> None:
        (self.root / "README.md").unlink()
        plan = plan_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            backup_root=self.backup_root,
        )
        result = apply_protected_source_removal(
            self.root,
            workspace_id="workspace-test",
            relative_path="README.md",
            removal_revision=plan.removal_revision,
            expected_manifest_sha256=plan.manifest_sha256,
            backup_root=self.backup_root,
        )

        self.assertEqual("removed", result.status)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(["keep"], [item["id"] for item in manifest["sources"]])

    def test_cli_plan_and_apply(self) -> None:
        db_path = self.backup_root / "events.db"
        store = EventStore(db_path)
        store.initialize()
        workspace = resolve_workspace(str(self.root), str(self.root), discovered_by="test")
        store.register_workspace(workspace)
        plan_stdout = StringIO()
        with redirect_stdout(plan_stdout):
            plan_exit = tooluseproxy_main(
                [
                    "protect", "remove", "plan", "--path", "README.md",
                    "--workspace", str(self.root), "--db", str(db_path), "--json",
                ]
            )
        self.assertEqual(0, plan_exit)
        plan = json.loads(plan_stdout.getvalue())
        self.assertEqual("review_required", plan["status"])

        apply_stdout = StringIO()
        with redirect_stdout(apply_stdout):
            apply_exit = tooluseproxy_main(
                [
                    "protect", "remove", "apply", "--path", "README.md",
                    "--removal-revision", plan["removal_revision"],
                    "--expected-manifest-sha256", plan["manifest_sha256"],
                    "--workspace", str(self.root), "--db", str(db_path), "--json",
                ]
            )
        self.assertEqual(0, apply_exit)
        self.assertEqual("removed", json.loads(apply_stdout.getvalue())["status"])

    def test_cli_error_does_not_print_source_content(self) -> None:
        db_path = self.backup_root / "events.db"
        store = EventStore(db_path)
        store.initialize()
        workspace = resolve_workspace(str(self.root), str(self.root), discovered_by="test")
        store.register_workspace(workspace)
        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = tooluseproxy_main(
                [
                    "protect", "remove", "plan", "--path", "missing.md",
                    "--workspace", str(self.root), "--db", str(db_path), "--json",
                ]
            )
        self.assertEqual(1, exit_code)
        self.assertNotIn("PRIVATE_CANARY", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
