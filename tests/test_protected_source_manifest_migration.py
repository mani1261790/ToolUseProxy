from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hook_monitor.analysis.source_index import load_sources_and_chunks
from tooluseproxy import protected_sources as migration_core
from tooluseproxy.protected_sources import (
    ProtectedSourceManifestMigrationPlan,
    ProtectedSourceRegistrationError,
    apply_protected_source_manifest_migration,
    plan_protected_source_manifest_migration,
)


@unittest.skipUnless(os.name == "posix", "protected source migration requires POSIX locks")
class ProtectedSourceManifestMigrationCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.backup_root = self.root / "data"
        self.workspace.mkdir()
        self.backup_root.mkdir(mode=0o700)
        self.backup_root.chmod(0o700)
        self.workspace_id = "workspace-migration-core"
        self.manifest_path = self.workspace / "protected_sources.json"

    def _write_source(self, path: str, body: str) -> None:
        target = self.workspace / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    def _write_manifest(
        self,
        payload: dict[str, object],
        *,
        canonical: bool = False,
    ) -> bytes:
        if canonical:
            encoded = (
                json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)
                + "\n"
            ).encode("utf-8")
        else:
            encoded = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        self.manifest_path.write_bytes(encoded)
        return encoded

    def _plan(
        self,
        *,
        workspace: Path | None = None,
        workspace_id: str | None = None,
    ) -> ProtectedSourceManifestMigrationPlan:
        return plan_protected_source_manifest_migration(
            self.workspace if workspace is None else workspace,
            workspace_id=self.workspace_id if workspace_id is None else workspace_id,
            backup_root=self.backup_root,
        )

    def _apply(
        self,
        plan: ProtectedSourceManifestMigrationPlan,
        *,
        workspace: Path | None = None,
        workspace_id: str | None = None,
        revision: str | None = None,
        expected_hash: str | None = None,
    ):
        assert plan.migration_revision is not None
        return apply_protected_source_manifest_migration(
            self.workspace if workspace is None else workspace,
            workspace_id=self.workspace_id if workspace_id is None else workspace_id,
            migration_revision=(
                plan.migration_revision if revision is None else revision
            ),
            expected_manifest_sha256=(
                plan.manifest_sha256 if expected_hash is None else expected_hash
            ),
            backup_root=self.backup_root,
        )

    def _assert_error(self, code: str, callback) -> ProtectedSourceRegistrationError:
        with self.assertRaises(ProtectedSourceRegistrationError) as raised:
            callback()
        self.assertEqual(code, raised.exception.code)
        return raised.exception

    def _backup_path(self, plan: ProtectedSourceManifestMigrationPlan) -> Path:
        self.assertIsNotNone(plan.backup_relative_path)
        assert plan.backup_relative_path is not None
        return self.backup_root / plan.backup_relative_path

    def _assert_no_backup(self) -> None:
        self.assertFalse((self.backup_root / "manifest-backups").exists())

    def test_omitted_schema_plan_adds_only_v2_contract_and_normalizes_format(self) -> None:
        self._write_source("private.txt", "private implementation\n")
        original = {
            "future_top": {"preserve": True},
            "sources": [
                {
                    "id": "private",
                    "path": "private.txt",
                    "type": "unpublished_impl",
                    "sensitivity": "high",
                    "policy_tags": ["no_external"],
                    "future_source": {"preserve": "yes"},
                }
            ],
            "trailing": "kept",
        }
        original_bytes = self._write_manifest(original)

        plan = self._plan()

        self.assertEqual("review_required", plan.status)
        self.assertEqual(1, plan.from_schema_version)
        self.assertTrue(plan.schema_version_was_omitted)
        self.assertEqual(2, plan.to_schema_version)
        self.assertEqual(1, plan.source_count)
        self.assertFalse(plan.sources_field_will_be_added)
        self.assertIsNone(plan.encoded_manifest)
        public = plan.to_public_payload()
        self.assertEqual("utf8_2_space_lf", public["formatting_policy"])
        self.assertEqual(0, public["selector_changes"])
        self.assertEqual(original_bytes, self.manifest_path.read_bytes())
        self._assert_no_backup()

        result = self._apply(plan)

        self.assertEqual("migrated", result.status)
        migrated = {"schema_version": 2, **original}
        expected = (
            json.dumps(migrated, ensure_ascii=False, indent=2, allow_nan=False)
            + "\n"
        ).encode("utf-8")
        self.assertEqual(expected, self.manifest_path.read_bytes())
        parsed = json.loads(expected)
        self.assertEqual(
            ["schema_version", "future_top", "sources", "trailing"],
            list(parsed),
        )
        self.assertEqual(original["sources"], parsed["sources"])
        self.assertNotIn("selector", parsed["sources"][0])

    def test_explicit_v1_preserves_top_and_source_order_unknown_fields_and_chunks(
        self,
    ) -> None:
        secret = "CORE.MIGRATION.PARITY.SECRET.5c7d"
        self._write_source(
            ".env.legacy",
            f"PRIVATE_TOKEN={secret}\nPUBLIC_MODE=demo\n",
        )
        sources = [
            {
                "future_before": "kept",
                "id": "legacy-env",
                "path": ".env.legacy",
                "type": "secretfile",
                "sensitivity": "high",
                "policy_tags": ["no_external"],
                "future_after": [1, 2, 3],
            }
        ]
        original = {
            "future_first": "kept",
            "schema_version": 1,
            "sources": sources,
            "future_last": {"nested": True},
        }
        original_bytes = self._write_manifest(original)
        before_sources, before_chunks = load_sources_and_chunks(
            self.workspace,
            workspace_id=self.workspace_id,
        )

        plan = self._plan()
        result = self._apply(plan)

        self.assertEqual("migrated", result.status)
        migrated = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(list(original), list(migrated))
        self.assertEqual(sources, migrated["sources"])
        self.assertNotIn("selector", migrated["sources"][0])
        after_sources, after_chunks = load_sources_and_chunks(
            self.workspace,
            workspace_id=self.workspace_id,
        )
        self.assertEqual(before_sources, after_sources)
        self.assertEqual(before_chunks, after_chunks)
        backup = self._backup_path(plan)
        self.assertEqual(original_bytes, backup.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))
        self.assertEqual(1, backup.stat().st_nlink)
        self.assertEqual(0o700, stat.S_IMODE(backup.parent.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(backup.parent.parent.stat().st_mode))

    def test_missing_sources_is_materialized_as_the_legacy_empty_default(self) -> None:
        original = {"schema_version": 1, "future": "kept"}
        self._write_manifest(original)

        plan = self._plan()

        self.assertTrue(plan.sources_field_will_be_added)
        self.assertEqual(0, plan.source_count)
        self._apply(plan)
        migrated = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {"schema_version": 2, "future": "kept", "sources": []},
            migrated,
        )

    def test_v2_plan_is_up_to_date_and_does_not_create_a_backup(self) -> None:
        original = self._write_manifest({"schema_version": 2, "sources": []})

        plan = self._plan()

        self.assertEqual("up_to_date", plan.status)
        self.assertFalse(plan.to_public_payload()["review_required"])
        self.assertIsNone(plan.migration_id)
        self.assertIsNone(plan.migration_revision)
        self.assertIsNone(plan.backup_relative_path)
        self.assertEqual(original, self.manifest_path.read_bytes())
        self._assert_no_backup()

    def test_revision_hash_and_workspace_commitment_fail_before_backup(self) -> None:
        self._write_source(".env", "TOKEN=secret\n")
        original = {
            "schema_version": 1,
            "sources": [
                {
                    "id": "env",
                    "path": ".env",
                    "type": "secretfile",
                    "sensitivity": "high",
                }
            ],
        }
        original_bytes = self._write_manifest(original)
        plan = self._plan()

        self._assert_error(
            "manifest_migration_revision_invalid",
            lambda: self._apply(plan, revision="m1_" + "0" * 64),
        )
        self._assert_no_backup()
        self._assert_error(
            "manifest_migration_conflict",
            lambda: self._apply(plan, expected_hash="0" * 64),
        )
        self._assert_no_backup()

        other_workspace = self.root / "other-workspace"
        other_workspace.mkdir()
        (other_workspace / ".env").write_text("TOKEN=other\n", encoding="utf-8")
        (other_workspace / "protected_sources.json").write_bytes(original_bytes)
        self._assert_error(
            "manifest_migration_revision_invalid",
            lambda: self._apply(
                plan,
                workspace=other_workspace,
                workspace_id="other-workspace-id",
            ),
        )
        self._assert_no_backup()

    def test_apply_is_idempotent_with_one_exact_private_backup(self) -> None:
        original = self._write_manifest({"schema_version": 1, "sources": []})
        plan = self._plan()

        first = self._apply(plan)
        manifest_after_first = self.manifest_path.read_bytes()
        backup = self._backup_path(plan)
        backup_stat = backup.stat()
        second = self._apply(plan)

        self.assertEqual("migrated", first.status)
        self.assertEqual("already_migrated", second.status)
        self.assertEqual(first.migration_id, second.migration_id)
        self.assertEqual(manifest_after_first, self.manifest_path.read_bytes())
        self.assertEqual(original, backup.read_bytes())
        self.assertEqual(backup_stat.st_ino, backup.stat().st_ino)
        self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))

    def test_exact_retry_does_not_depend_on_current_source_file_availability(
        self,
    ) -> None:
        self._write_source("private.txt", "private source body\n")
        self._write_manifest(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "id": "private",
                        "path": "private.txt",
                        "type": "unpublished_impl",
                        "sensitivity": "high",
                    }
                ],
            }
        )
        plan = self._plan()
        self.assertEqual("migrated", self._apply(plan).status)

        (self.workspace / "private.txt").unlink()

        self.assertEqual("already_migrated", self._apply(plan).status)

    def test_retry_rejects_missing_corrupt_symlink_and_hardlinked_backup(self) -> None:
        original = self._write_manifest({"schema_version": 1, "sources": []})
        plan = self._plan()
        self._apply(plan)
        backup = self._backup_path(plan)

        backup.unlink()
        self._assert_error("manifest_backup_missing", lambda: self._apply(plan))

        backup.write_bytes(b"{\"schema_version\":1,\"sources\":[1]}")
        backup.chmod(0o600)
        self._assert_error("manifest_backup_conflict", lambda: self._apply(plan))

        backup.unlink()
        symlink_target = self.root / "symlink-target.json"
        symlink_target.write_bytes(original)
        symlink_target.chmod(0o600)
        backup.symlink_to(symlink_target)
        self._assert_error("manifest_backup_conflict", lambda: self._apply(plan))

        backup.unlink()
        backup.write_bytes(original)
        backup.chmod(0o600)
        second_link = self.root / "backup-hardlink.json"
        os.link(backup, second_link)
        self._assert_error("manifest_backup_conflict", lambda: self._apply(plan))

    def test_manifest_change_before_and_during_install_is_not_overwritten(self) -> None:
        original = {"schema_version": 1, "sources": []}
        self._write_manifest(original)
        plan = self._plan()
        externally_changed = {
            "schema_version": 1,
            "sources": [],
            "external": "before-apply",
        }
        changed_bytes = self._write_manifest(externally_changed)

        self._assert_error("manifest_migration_conflict", lambda: self._apply(plan))
        self.assertEqual(changed_bytes, self.manifest_path.read_bytes())
        self._assert_no_backup()

        self._write_manifest(original)
        plan = self._plan()
        real_write_temporary = migration_core._write_temporary_manifest

        def write_then_edit(root_fd: int, encoded: bytes) -> str:
            temporary_name = real_write_temporary(root_fd, encoded)
            self._write_manifest(
                {
                    "schema_version": 1,
                    "sources": [],
                    "external": "during-apply",
                }
            )
            return temporary_name

        with patch(
            "tooluseproxy.protected_sources._write_temporary_manifest",
            side_effect=write_then_edit,
        ):
            self._assert_error(
                "manifest_migration_conflict",
                lambda: self._apply(plan),
            )
        self.assertEqual(
            "during-apply",
            json.loads(self.manifest_path.read_text(encoding="utf-8"))["external"],
        )

    def test_replace_failure_keeps_original_and_exact_backup_then_retries(self) -> None:
        original = self._write_manifest({"schema_version": 1, "sources": []})
        plan = self._plan()

        with patch(
            "tooluseproxy.protected_sources.os.replace",
            side_effect=OSError("injected replace failure"),
        ):
            self._assert_error("manifest_write_failed", lambda: self._apply(plan))

        self.assertEqual(original, self.manifest_path.read_bytes())
        self.assertEqual(original, self._backup_path(plan).read_bytes())
        self.assertEqual("migrated", self._apply(plan).status)

    def test_directory_fsync_failure_after_replace_recovers_on_exact_retry(self) -> None:
        self._write_manifest({"schema_version": 1, "sources": []})
        plan = self._plan()
        workspace_stat = self.workspace.stat()
        real_fsync = os.fsync

        def fail_workspace_directory(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (
                stat.S_ISDIR(metadata.st_mode)
                and metadata.st_dev == workspace_stat.st_dev
                and metadata.st_ino == workspace_stat.st_ino
            ):
                raise OSError("injected directory fsync failure")
            real_fsync(descriptor)

        with patch(
            "tooluseproxy.protected_sources.os.fsync",
            side_effect=fail_workspace_directory,
        ):
            self._assert_error(
                "manifest_durability_unknown",
                lambda: self._apply(plan),
            )

        self.assertEqual(
            plan.result_manifest_sha256,
            migration_core.hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
        )
        self.assertEqual("already_migrated", self._apply(plan).status)

    def test_postcondition_failure_after_replace_recovers_on_exact_retry(self) -> None:
        self._write_manifest({"schema_version": 1, "sources": []})
        plan = self._plan()
        real_read_manifest = migration_core._read_manifest_text
        read_count = 0

        def fail_installed_read(*args: object, **kwargs: object):
            nonlocal read_count
            read_count += 1
            if read_count == 3:
                raise ProtectedSourceRegistrationError("manifest_not_safe")
            return real_read_manifest(*args, **kwargs)

        with patch(
            "tooluseproxy.protected_sources._read_manifest_text",
            side_effect=fail_installed_read,
        ):
            self._assert_error(
                "manifest_postcondition_failed",
                lambda: self._apply(plan),
            )

        self.assertEqual(
            plan.result_manifest_sha256,
            migration_core.hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
        )
        self.assertEqual("already_migrated", self._apply(plan).status)

    def test_privacy_sentinel_is_absent_from_plan_result_repr_and_errors(self) -> None:
        sentinel = "MIGRATION.PRIVACY.SENTINEL.8bb8"
        self._write_source("private.txt", "private source body\n")
        self._write_manifest(
            {
                "schema_version": 1,
                "private_unknown_metadata": sentinel,
                "sources": [
                    {
                        "id": "private",
                        "path": "private.txt",
                        "type": "unpublished_impl",
                        "sensitivity": "high",
                    }
                ],
            }
        )

        plan = self._plan()
        rendered_plan = json.dumps(plan.to_public_payload(), ensure_ascii=False)
        self.assertNotIn(sentinel, rendered_plan)
        self.assertNotIn(sentinel, repr(plan))
        self.assertIsNone(plan.encoded_manifest)
        error = self._assert_error(
            "manifest_migration_revision_invalid",
            lambda: self._apply(plan, revision="m1_" + "f" * 64),
        )
        self.assertNotIn(sentinel, str(error))

        result = self._apply(plan)
        self.assertNotIn(
            sentinel,
            json.dumps(result.to_public_payload(), ensure_ascii=False),
        )
        self.assertNotIn(sentinel, repr(result))


if __name__ == "__main__":
    unittest.main()
