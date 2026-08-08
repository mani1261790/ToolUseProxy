from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.desktop_update_rollback_state import (
    ArtifactIdentity,
    DesktopUpdateStateError,
    apply_transition,
    make_cleanup_token,
    make_rollback_token,
    new_state,
    read_state,
    validate_confirmation,
    validate_distinct_artifacts,
    write_state,
)


def _digest(character: str) -> str:
    return character * 64


class DesktopUpdateRollbackStateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.old = ArtifactIdentity(
            role="old",
            declared_version="0.1.0-alpha.1",
            python_version="0.1.0a1",
            source_commit="2" * 40,
            source_artifact_sha256=_digest("1"),
            plugin_tree_sha256=_digest("2"),
            hook_definition_sha256=_digest("3"),
            launcher_sha256=_digest("4"),
            marketplace="tooluseproxy-desktop-update",
            plugin_id="tooluseproxy@tooluseproxy-desktop-update",
            plugin_root="/tmp/old/tooluseproxy",
        )
        self.new = ArtifactIdentity(
            role="new",
            declared_version="0.1.0-alpha.3",
            python_version="0.1.0a3",
            source_commit="c" * 40,
            source_artifact_sha256=_digest("a"),
            plugin_tree_sha256=_digest("b"),
            hook_definition_sha256=_digest("c"),
            launcher_sha256=_digest("d"),
            marketplace="tooluseproxy-desktop-update",
            plugin_id="tooluseproxy@tooluseproxy-desktop-update",
            plugin_root="/tmp/new/tooluseproxy",
        )

    def _state(self, root: Path) -> dict[str, object]:
        return new_state(
            root=root,
            codex_home=root / "codex-home",
            workspace=root / "workspace",
            current_data=root / "current-data",
            rollback_data=root / "rollback-data",
            old=self.old,
            new=self.new,
            before={"installed_plugin_ids": []},
            confirmation_token="plan-token",
        )

    def _plugin_evidence(self, identity: ArtifactIdentity) -> dict[str, object]:
        return {
            "plugin_id": identity.plugin_id,
            "version": identity.declared_version,
            "tree_sha256": identity.effective_tree_sha256,
            "hook_definition_sha256": identity.hook_definition_sha256,
            "launcher_sha256": identity.launcher_sha256,
            "trusted_hook_count": 3,
            "hook_events": ["PostToolUse", "PreToolUse", "Stop"],
        }

    def test_artifacts_must_differ_in_version_commit_artifact_and_tree(self) -> None:
        validate_distinct_artifacts(self.old, self.new)
        same_version = ArtifactIdentity(
            **{
                **self.new.__dict__,
                "declared_version": self.old.declared_version,
            }
        )
        with self.assertRaisesRegex(
            DesktopUpdateStateError,
            "artifacts_not_distinct_declared_version",
        ):
            validate_distinct_artifacts(self.old, same_version)

    def test_update_and_safe_rollback_state_machine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            state = self._state(root)
            state = apply_transition(
                state,
                target_stage="old_marketplace_added",
                evidence={
                    "marketplace_name": self.old.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="old_plugin_installed",
                evidence=self._plugin_evidence(self.old),
            )
            state = apply_transition(
                state,
                target_stage="baseline_initialized",
                evidence={
                    "status": "active",
                    "database_schema": 1,
                    "baseline_event_present": True,
                    "workspace_registered": True,
                    "data_path": str(root / "current-data"),
                },
            )
            state = apply_transition(
                state,
                target_stage="old_removed_for_update",
                evidence={
                    "plugin_present": False,
                    "managed_data_present": True,
                    "database_schema": 1,
                    "baseline_event_count_preserved": True,
                    "workspace_registered": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="new_marketplace_added",
                evidence={
                    "marketplace_name": self.new.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="new_plugin_installed",
                evidence=self._plugin_evidence(self.new),
            )
            state = apply_transition(
                state,
                target_stage="updated",
                evidence={
                    "status": "active",
                    "database_schema": 6,
                    "migration_backup_schema": 1,
                    "baseline_event_present": True,
                    "workspace_registered": True,
                    "runtime_settings_active": True,
                    "public_side_effect_count": 1,
                    "protected_side_effect_count": 0,
                    "exact_block_count": 1,
                    "raw_protected_value_exposure": 0,
                },
            )
            state["migration_backup"] = str(
                root / "current-data" / "events.db.pre-migration-v1.bak"
            )
            state = apply_transition(
                state,
                target_stage="new_removed_for_rollback",
                evidence={
                    "plugin_present": False,
                    "managed_data_present": True,
                    "managed_data_preserved": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="old_marketplace_readded",
                evidence={
                    "marketplace_name": self.old.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="old_plugin_reinstalled",
                evidence=self._plugin_evidence(self.old),
            )
            state = apply_transition(
                state,
                target_stage="rollback_incompatible_confirmed",
                evidence={
                    "status": "inactive",
                    "database_schema": 6,
                    "database_hash_unchanged": True,
                    "event_count_unchanged": True,
                },
            )
            rollback_token, state = make_rollback_token(state)
            validate_confirmation(
                state["rollback_confirmation_sha256"],
                rollback_token,
                stage="rollback_restore_apply",
            )
            state = apply_transition(
                state,
                target_stage="rollback_restored",
                evidence={
                    "current_data_path": str(root / "current-data"),
                    "rollback_data_path": str(root / "rollback-data"),
                    "paths_are_separate": True,
                    "current_database_schema": 6,
                    "rollback_database_schema": 1,
                    "rollback_status": "active",
                    "baseline_event_present": True,
                    "post_update_event_absent": True,
                    "current_database_preserved": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="direct_remove_planned",
                evidence={
                    "plugin_enabled": True,
                    "probe_gate_armed": True,
                    "managed_data_present": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="direct_plugin_removed",
                evidence={
                    "plugin_present": False,
                    "managed_data_present": True,
                    "managed_data_hash_unchanged": True,
                },
            )
            state = apply_transition(
                state,
                target_stage="direct_remove_verified",
                evidence={
                    "remove_started_while_enabled": True,
                    "plugin_present": False,
                    "managed_data_present": True,
                    "new_task_hook_count": 0,
                    "existing_task_hook_count": 3,
                },
            )
            token, state = make_cleanup_token(state)
            validate_confirmation(
                state["cleanup_confirmation_sha256"],
                token,
                stage="cleanup_apply",
            )
            state = apply_transition(
                state,
                target_stage="restored",
                evidence={
                    "managed_data_removed": True,
                    "workspace_removed": True,
                    "marketplace_removed": True,
                    "shared_inventory_restored": True,
                    "raw_protected_value_exposure": 0,
                },
            )
            state_path = root / "state.json"
            write_state(state_path, state)
            restored = read_state(state_path)
            self.assertEqual("restored", restored["stage"])

    def test_transition_order_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            state = self._state(Path(temporary_directory).resolve())
            with self.assertRaisesRegex(
                DesktopUpdateStateError,
                "state_transition_invalid",
            ):
                apply_transition(
                    state,
                    target_stage="updated",
                    evidence={},
                )

    def test_old_runtime_must_not_mutate_new_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            state = self._advance_to_old_reinstalled(self._state(root), root)
            with self.assertRaisesRegex(
                DesktopUpdateStateError,
                "database_hash_unchanged_invalid",
            ):
                apply_transition(
                    state,
                    target_stage="rollback_incompatible_confirmed",
                    evidence={
                        "status": "inactive",
                        "database_schema": 6,
                        "database_hash_unchanged": False,
                        "event_count_unchanged": True,
                    },
                )

    def test_rollback_data_directory_must_be_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            with self.assertRaisesRegex(
                DesktopUpdateStateError,
                "rollback_data_not_separate",
            ):
                new_state(
                    root=root,
                    codex_home=root / "codex-home",
                    workspace=root / "workspace",
                    current_data=root / "data",
                    rollback_data=root / "data",
                    old=self.old,
                    new=self.new,
                    before={},
                    confirmation_token="token",
                )

    def test_raw_secret_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            state = self._state(root)
            state = apply_transition(
                state,
                target_stage="old_marketplace_added",
                evidence={
                    "marketplace_name": self.old.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            )
            evidence = self._plugin_evidence(self.old)
            evidence["secret_value"] = "synthetic-secret"
            with self.assertRaisesRegex(
                DesktopUpdateStateError,
                "raw_protected_value_field_forbidden",
            ):
                apply_transition(
                    state,
                    target_stage="old_plugin_installed",
                    evidence=evidence,
                )

    def _advance_to_old_reinstalled(
        self,
        state: dict[str, object],
        root: Path,
    ) -> dict[str, object]:
        transitions = (
            (
                "old_marketplace_added",
                {
                    "marketplace_name": self.old.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            ),
            ("old_plugin_installed", self._plugin_evidence(self.old)),
            (
                "baseline_initialized",
                {
                    "status": "active",
                    "database_schema": 1,
                    "baseline_event_present": True,
                    "workspace_registered": True,
                    "data_path": str(root / "current-data"),
                },
            ),
            (
                "old_removed_for_update",
                {
                    "plugin_present": False,
                    "managed_data_present": True,
                    "database_schema": 1,
                    "baseline_event_count_preserved": True,
                    "workspace_registered": True,
                },
            ),
            (
                "new_marketplace_added",
                {
                    "marketplace_name": self.new.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            ),
            ("new_plugin_installed", self._plugin_evidence(self.new)),
            (
                "updated",
                {
                    "status": "active",
                    "database_schema": 6,
                    "migration_backup_schema": 1,
                    "baseline_event_present": True,
                    "workspace_registered": True,
                    "runtime_settings_active": True,
                    "public_side_effect_count": 1,
                    "protected_side_effect_count": 0,
                    "exact_block_count": 1,
                    "raw_protected_value_exposure": 0,
                },
            ),
            (
                "new_removed_for_rollback",
                {
                    "plugin_present": False,
                    "managed_data_present": True,
                    "managed_data_preserved": True,
                },
            ),
            (
                "old_marketplace_readded",
                {
                    "marketplace_name": self.old.marketplace,
                    "plugin_present": False,
                    "shared_inventory_delta_valid": True,
                },
            ),
            ("old_plugin_reinstalled", self._plugin_evidence(self.old)),
        )
        for stage, evidence in transitions:
            state = apply_transition(
                state,
                target_stage=stage,
                evidence=evidence,
            )
        return state


if __name__ == "__main__":
    unittest.main()
