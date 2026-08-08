from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


STATE_SCHEMA_VERSION = 1
CASE_ID = "desktop-update-rollback-v1"
SURFACE = "codex_desktop"

STAGES = (
    "planned",
    "old_marketplace_added",
    "old_plugin_installed",
    "baseline_initialized",
    "old_removed_for_update",
    "new_marketplace_added",
    "new_plugin_installed",
    "updated",
    "new_removed_for_rollback",
    "old_marketplace_readded",
    "old_plugin_reinstalled",
    "rollback_incompatible_confirmed",
    "rollback_restore_planned",
    "rollback_restored",
    "direct_remove_planned",
    "direct_plugin_removed",
    "direct_remove_verified",
    "cleanup_planned",
    "restored",
)

NEXT_STAGE = {
    current: following
    for current, following in zip(STAGES, STAGES[1:])
}


class DesktopUpdateStateError(RuntimeError):
    def __init__(self, stage: str, code: str) -> None:
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}: {code}")


@dataclass(frozen=True)
class ArtifactIdentity:
    role: str
    declared_version: str
    python_version: str
    source_commit: str
    source_artifact_sha256: str
    plugin_tree_sha256: str
    hook_definition_sha256: str
    launcher_sha256: str
    marketplace: str
    plugin_id: str
    plugin_root: str
    instrumented_tree_sha256: str | None = None
    instrumented_files: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "declared_version": self.declared_version,
            "python_version": self.python_version,
            "source_commit": self.source_commit,
            "source_artifact_sha256": self.source_artifact_sha256,
            "plugin_tree_sha256": self.plugin_tree_sha256,
            "hook_definition_sha256": self.hook_definition_sha256,
            "launcher_sha256": self.launcher_sha256,
            "marketplace": self.marketplace,
            "plugin_id": self.plugin_id,
            "plugin_root": self.plugin_root,
            "instrumented_tree_sha256": self.instrumented_tree_sha256,
            "instrumented_files": list(self.instrumented_files),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ArtifactIdentity:
        required_strings = (
            "role",
            "declared_version",
            "python_version",
            "source_commit",
            "source_artifact_sha256",
            "plugin_tree_sha256",
            "hook_definition_sha256",
            "launcher_sha256",
            "marketplace",
            "plugin_id",
            "plugin_root",
        )
        if any(
            not isinstance(payload.get(key), str) or not payload[key]
            for key in required_strings
        ):
            raise DesktopUpdateStateError("identity", "artifact_identity_invalid")
        instrumented_hash = payload.get("instrumented_tree_sha256")
        if instrumented_hash is not None and not isinstance(instrumented_hash, str):
            raise DesktopUpdateStateError("identity", "instrumented_hash_invalid")
        files = payload.get("instrumented_files", [])
        if not isinstance(files, list) or any(
            not isinstance(item, str) or not item for item in files
        ):
            raise DesktopUpdateStateError("identity", "instrumented_files_invalid")
        return cls(
            **{key: str(payload[key]) for key in required_strings},
            instrumented_tree_sha256=instrumented_hash,
            instrumented_files=tuple(files),
        )

    @property
    def effective_tree_sha256(self) -> str:
        return self.instrumented_tree_sha256 or self.plugin_tree_sha256


def validate_distinct_artifacts(
    old: ArtifactIdentity,
    new: ArtifactIdentity,
) -> None:
    if old.role != "old" or new.role != "new":
        raise DesktopUpdateStateError("plan", "artifact_roles_invalid")
    comparisons = {
        "declared_version": (
            old.declared_version,
            new.declared_version,
        ),
        "source_commit": (old.source_commit, new.source_commit),
        "source_artifact_sha256": (
            old.source_artifact_sha256,
            new.source_artifact_sha256,
        ),
        "effective_tree_sha256": (
            old.effective_tree_sha256,
            new.effective_tree_sha256,
        ),
    }
    same = [name for name, values in comparisons.items() if values[0] == values[1]]
    if same:
        raise DesktopUpdateStateError(
            "plan",
            "artifacts_not_distinct_" + "_".join(sorted(same)),
        )
    if old.marketplace != new.marketplace or old.plugin_id != new.plugin_id:
        raise DesktopUpdateStateError("plan", "update_channel_identity_changed")
    for identity in (old, new):
        _validate_sha256(identity.source_artifact_sha256, "source_artifact")
        _validate_sha256(identity.plugin_tree_sha256, "plugin_tree")
        _validate_sha256(identity.hook_definition_sha256, "hook_definition")
        _validate_sha256(identity.launcher_sha256, "launcher")
        if identity.instrumented_tree_sha256 is not None:
            _validate_sha256(identity.instrumented_tree_sha256, "instrumented_tree")


def new_state(
    *,
    root: Path,
    codex_home: Path,
    workspace: Path,
    current_data: Path,
    rollback_data: Path,
    old: ArtifactIdentity,
    new: ArtifactIdentity,
    before: Mapping[str, Any],
    confirmation_token: str,
) -> dict[str, Any]:
    validate_distinct_artifacts(old, new)
    paths = {
        "root": root,
        "codex_home": codex_home,
        "workspace": workspace,
        "current_data": current_data,
        "rollback_data": rollback_data,
    }
    normalized = {name: path.expanduser().resolve() for name, path in paths.items()}
    if normalized["current_data"] == normalized["rollback_data"]:
        raise DesktopUpdateStateError("plan", "rollback_data_not_separate")
    if not confirmation_token:
        raise DesktopUpdateStateError("plan", "confirmation_token_missing")
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "case_id": CASE_ID,
        "surface": SURFACE,
        "stage": "planned",
        **{name: str(path) for name, path in normalized.items()},
        "old": old.as_dict(),
        "new": new.as_dict(),
        "before": dict(before),
        "plan_confirmation_sha256": _text_sha256(confirmation_token),
        "cleanup_confirmation_sha256": None,
        "evidence": {},
    }


def apply_transition(
    state: Mapping[str, Any],
    *,
    target_stage: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    current = _validated_state(state)
    current_stage = str(current["stage"])
    if NEXT_STAGE.get(current_stage) != target_stage:
        raise DesktopUpdateStateError(target_stage, "state_transition_invalid")
    old = ArtifactIdentity.from_dict(_mapping(current["old"], target_stage))
    new = ArtifactIdentity.from_dict(_mapping(current["new"], target_stage))
    validate_distinct_artifacts(old, new)
    normalized_evidence = dict(evidence)
    _validate_stage_evidence(
        current,
        target_stage=target_stage,
        evidence=normalized_evidence,
        old=old,
        new=new,
    )
    result = dict(current)
    all_evidence = dict(_mapping(current.get("evidence", {}), target_stage))
    all_evidence[target_stage] = normalized_evidence
    result["evidence"] = all_evidence
    result["stage"] = target_stage
    return result


def write_state(path: Path, state: Mapping[str, Any]) -> None:
    validated = _validated_state(state)
    rendered = json.dumps(
        validated,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _reject_sensitive_evidence(rendered)
    requested = path.expanduser()
    if _path_or_ancestor_is_symlink(requested):
        raise DesktopUpdateStateError("state_write", "symlink_refused")
    path = requested.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise DesktopUpdateStateError("state_write", "write_failed") from error


def read_state(path: Path) -> dict[str, Any]:
    requested = path.expanduser()
    if _path_or_ancestor_is_symlink(requested):
        raise DesktopUpdateStateError("state_read", "state_unavailable")
    path = requested.resolve()
    if not path.is_file():
        raise DesktopUpdateStateError("state_read", "state_unavailable")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DesktopUpdateStateError("state_read", "state_invalid") from error
    return _validated_state(payload)


def _path_or_ancestor_is_symlink(path: Path) -> bool:
    current = path.absolute()
    while True:
        if current.is_symlink():
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def make_cleanup_token(state: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    current = _validated_state(state)
    if current["stage"] != "direct_remove_verified":
        raise DesktopUpdateStateError("cleanup_plan", "state_stage_mismatch")
    token = secrets.token_hex(24)
    result = dict(current)
    result["cleanup_confirmation_sha256"] = _text_sha256(token)
    result = apply_transition(
        result,
        target_stage="cleanup_planned",
        evidence={
            "managed_data_paths": [
                result["current_data"],
                result["rollback_data"],
            ],
            "workspace": result["workspace"],
            "marketplace": _mapping(result["old"], "cleanup_plan")["marketplace"],
        },
    )
    return token, result


def make_rollback_token(state: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    current = _validated_state(state)
    if current["stage"] != "rollback_incompatible_confirmed":
        raise DesktopUpdateStateError(
            "rollback_restore_plan",
            "state_stage_mismatch",
        )
    backup = current.get("migration_backup")
    if not isinstance(backup, str) or not Path(backup).is_absolute():
        raise DesktopUpdateStateError(
            "rollback_restore_plan",
            "migration_backup_missing",
        )
    token = secrets.token_hex(24)
    result = dict(current)
    result["rollback_confirmation_sha256"] = _text_sha256(token)
    result = apply_transition(
        result,
        target_stage="rollback_restore_planned",
        evidence={
            "source_backup": backup,
            "current_data_path": result["current_data"],
            "rollback_data_path": result["rollback_data"],
            "current_data_will_be_overwritten": False,
        },
    )
    return token, result


def validate_confirmation(
    expected_sha256: Any,
    provided_token: str,
    *,
    stage: str,
) -> None:
    if (
        not isinstance(expected_sha256, str)
        or not secrets.compare_digest(
            expected_sha256,
            _text_sha256(provided_token),
        )
    ):
        raise DesktopUpdateStateError(stage, "confirmation_token_invalid")


def _validate_stage_evidence(
    state: Mapping[str, Any],
    *,
    target_stage: str,
    evidence: Mapping[str, Any],
    old: ArtifactIdentity,
    new: ArtifactIdentity,
) -> None:
    if target_stage in {
        "old_marketplace_added",
        "new_marketplace_added",
        "old_marketplace_readded",
    }:
        _require(evidence, "marketplace_name", old.marketplace, target_stage)
        _require(evidence, "plugin_present", False, target_stage)
        _require(evidence, "shared_inventory_delta_valid", True, target_stage)
    elif target_stage in {"old_plugin_installed", "old_plugin_reinstalled"}:
        _validate_plugin_evidence(evidence, old, trusted_required=True)
    elif target_stage == "baseline_initialized":
        _require(evidence, "status", "active", target_stage)
        _require(evidence, "database_schema", 1, target_stage)
        _require(evidence, "baseline_event_present", True, target_stage)
        _require(evidence, "workspace_registered", True, target_stage)
        _require_path(
            evidence,
            "data_path",
            Path(str(state["current_data"])),
            target_stage,
        )
    elif target_stage == "old_removed_for_update":
        _require(evidence, "plugin_present", False, target_stage)
        _require(evidence, "managed_data_present", True, target_stage)
        _require(evidence, "database_schema", 1, target_stage)
        _require(evidence, "baseline_event_count_preserved", True, target_stage)
        _require(evidence, "workspace_registered", True, target_stage)
    elif target_stage == "new_removed_for_rollback":
        _require(evidence, "plugin_present", False, target_stage)
        _require(evidence, "managed_data_present", True, target_stage)
        _require(evidence, "managed_data_preserved", True, target_stage)
    elif target_stage == "new_plugin_installed":
        _validate_plugin_evidence(evidence, new, trusted_required=True)
    elif target_stage == "updated":
        _require(evidence, "status", "active", target_stage)
        _require(evidence, "database_schema", 6, target_stage)
        _require(evidence, "migration_backup_schema", 1, target_stage)
        _require(evidence, "baseline_event_present", True, target_stage)
        _require(evidence, "workspace_registered", True, target_stage)
        _require(evidence, "runtime_settings_active", True, target_stage)
        _require(evidence, "public_side_effect_count", 1, target_stage)
        _require(evidence, "protected_side_effect_count", 0, target_stage)
        _require(evidence, "exact_block_count", 1, target_stage)
        _require(evidence, "raw_protected_value_exposure", 0, target_stage)
    elif target_stage == "rollback_incompatible_confirmed":
        _require(evidence, "status", "inactive", target_stage)
        _require(evidence, "database_schema", 6, target_stage)
        _require(evidence, "database_hash_unchanged", True, target_stage)
        _require(evidence, "event_count_unchanged", True, target_stage)
    elif target_stage == "rollback_restore_planned":
        migration_backup = state.get("migration_backup")
        if not isinstance(migration_backup, str) or not migration_backup:
            raise DesktopUpdateStateError(
                target_stage,
                "migration_backup_missing",
            )
        _require_path(
            evidence,
            "source_backup",
            Path(migration_backup),
            target_stage,
        )
        _require_path(
            evidence,
            "current_data_path",
            Path(str(state["current_data"])),
            target_stage,
        )
        _require_path(
            evidence,
            "rollback_data_path",
            Path(str(state["rollback_data"])),
            target_stage,
        )
        _require(
            evidence,
            "current_data_will_be_overwritten",
            False,
            target_stage,
        )
    elif target_stage == "rollback_restored":
        _require_path(
            evidence,
            "current_data_path",
            Path(str(state["current_data"])),
            target_stage,
        )
        _require_path(
            evidence,
            "rollback_data_path",
            Path(str(state["rollback_data"])),
            target_stage,
        )
        _require(evidence, "paths_are_separate", True, target_stage)
        _require(evidence, "current_database_schema", 6, target_stage)
        _require(evidence, "rollback_database_schema", 1, target_stage)
        _require(evidence, "rollback_status", "active", target_stage)
        _require(evidence, "baseline_event_present", True, target_stage)
        _require(evidence, "post_update_event_absent", True, target_stage)
        _require(evidence, "current_database_preserved", True, target_stage)
    elif target_stage == "direct_remove_verified":
        _require(evidence, "remove_started_while_enabled", True, target_stage)
        _require(evidence, "plugin_present", False, target_stage)
        _require(evidence, "managed_data_present", True, target_stage)
        _require(evidence, "new_task_hook_count", 0, target_stage)
        if evidence.get("existing_task_hook_count") is not None and not isinstance(
            evidence.get("existing_task_hook_count"),
            int,
        ):
            raise DesktopUpdateStateError(
                target_stage,
                "existing_task_hook_count_invalid",
            )
    elif target_stage == "direct_remove_planned":
        _require(evidence, "plugin_enabled", True, target_stage)
        _require(evidence, "probe_gate_armed", True, target_stage)
        _require(evidence, "managed_data_present", True, target_stage)
    elif target_stage == "direct_plugin_removed":
        _require(evidence, "plugin_present", False, target_stage)
        _require(evidence, "managed_data_present", True, target_stage)
        _require(evidence, "managed_data_hash_unchanged", True, target_stage)
    elif target_stage == "cleanup_planned":
        paths = evidence.get("managed_data_paths")
        if not isinstance(paths, list) or set(paths) != {
            str(state["current_data"]),
            str(state["rollback_data"]),
        }:
            raise DesktopUpdateStateError(target_stage, "cleanup_paths_invalid")
        _require_path(
            evidence,
            "workspace",
            Path(str(state["workspace"])),
            target_stage,
        )
    elif target_stage == "restored":
        _require(evidence, "managed_data_removed", True, target_stage)
        _require(evidence, "workspace_removed", True, target_stage)
        _require(evidence, "marketplace_removed", True, target_stage)
        _require(evidence, "shared_inventory_restored", True, target_stage)
        _require(evidence, "raw_protected_value_exposure", 0, target_stage)
    else:
        raise DesktopUpdateStateError(target_stage, "stage_validator_missing")
    _reject_sensitive_evidence(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True),
    )


def _validate_plugin_evidence(
    evidence: Mapping[str, Any],
    identity: ArtifactIdentity,
    *,
    trusted_required: bool,
) -> None:
    stage = "plugin_checkpoint"
    _require(evidence, "plugin_id", identity.plugin_id, stage)
    _require(evidence, "version", identity.declared_version, stage)
    _require(evidence, "tree_sha256", identity.effective_tree_sha256, stage)
    _require(evidence, "hook_definition_sha256", identity.hook_definition_sha256, stage)
    _require(evidence, "launcher_sha256", identity.launcher_sha256, stage)
    if trusted_required:
        _require(evidence, "trusted_hook_count", 3, stage)
        _require(evidence, "hook_events", ["PostToolUse", "PreToolUse", "Stop"], stage)


def _validated_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, Mapping):
        raise DesktopUpdateStateError("state", "state_object_required")
    result = dict(state)
    if result.get("schema_version") != STATE_SCHEMA_VERSION:
        raise DesktopUpdateStateError("state", "state_schema_unsupported")
    if result.get("case_id") != CASE_ID or result.get("surface") != SURFACE:
        raise DesktopUpdateStateError("state", "state_identity_mismatch")
    if result.get("stage") not in STAGES:
        raise DesktopUpdateStateError("state", "state_stage_invalid")
    for key in (
        "root",
        "codex_home",
        "workspace",
        "current_data",
        "rollback_data",
    ):
        if not isinstance(result.get(key), str) or not Path(result[key]).is_absolute():
            raise DesktopUpdateStateError("state", f"{key}_invalid")
    if Path(result["current_data"]) == Path(result["rollback_data"]):
        raise DesktopUpdateStateError("state", "rollback_data_not_separate")
    ArtifactIdentity.from_dict(_mapping(result.get("old"), "state"))
    ArtifactIdentity.from_dict(_mapping(result.get("new"), "state"))
    if not isinstance(result.get("evidence"), Mapping):
        raise DesktopUpdateStateError("state", "evidence_invalid")
    return result


def _mapping(value: Any, stage: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DesktopUpdateStateError(stage, "object_required")
    return value


def _require(
    evidence: Mapping[str, Any],
    key: str,
    expected: Any,
    stage: str,
) -> None:
    if evidence.get(key) != expected:
        raise DesktopUpdateStateError(stage, f"{key}_invalid")


def _require_path(
    evidence: Mapping[str, Any],
    key: str,
    expected: Path,
    stage: str,
) -> None:
    value = evidence.get(key)
    if not isinstance(value, str) or Path(value).expanduser().resolve() != expected.resolve():
        raise DesktopUpdateStateError(stage, f"{key}_invalid")


def _validate_sha256(value: str, name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DesktopUpdateStateError("identity", f"{name}_sha256_invalid")


def _reject_sensitive_evidence(rendered: str) -> None:
    forbidden_keys = (
        '"protected_value"',
        '"secret_value"',
        '"raw_payload"',
        '"source_content"',
    )
    if any(key in rendered for key in forbidden_keys):
        raise DesktopUpdateStateError("privacy", "raw_protected_value_field_forbidden")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
