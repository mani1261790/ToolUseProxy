#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_BUILDER = REPO_ROOT / "scripts" / "build_release_candidate.py"
BASELINE_COMMIT = "22974427ab62e55a00d21af164d8fc837cb5e8b7"
BASELINE_PLUGIN_VERSION = "0.1.0-alpha.1"
BASELINE_PYTHON_VERSION = "0.1.0a1"
BASELINE_SCHEMA_VERSION = 1
SYNTHETIC_MARKER = "LIFECYCLE.CANARY.8B4E2D91"


class LifecycleFailure(RuntimeError):
    def __init__(self, stage: str, code: str) -> None:
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}: {code}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rehearse ToolUseProxy install, upgrade, rollback, remove, and explicit "
            "managed-data uninstall with immutable synthetic inputs."
        ),
    )
    parser.add_argument(
        "--installation-mode",
        choices=("codex", "extracted"),
        default="codex",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        help="Use an existing verified release candidate directory.",
    )
    args = parser.parse_args()
    try:
        payload = rehearse_lifecycle(args.installation_mode, args.candidate)
    except LifecycleFailure as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "stage": error.stage,
                    "error_code": error.code,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(payload, sort_keys=True))
    return 0


def rehearse_lifecycle(
    installation_mode: str,
    candidate: Path | None,
) -> dict[str, Any]:
    stage = "prepare"
    captured_outputs: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="tooluseproxy-lifecycle-rehearsal-"
    ) as temporary_directory:
        root = Path(temporary_directory)
        workspace = root / "workspace"
        codex_home = root / "codex-home"
        baseline_marketplace = root / "baseline-marketplace"
        current_marketplace = root / "current-marketplace"
        current_data = root / "current-data"
        rollback_data = root / "rollback-data"
        workspace.mkdir()
        codex_home.mkdir()

        stage = "baseline_extract"
        _extract_git_archive(BASELINE_COMMIT, baseline_marketplace, captured_outputs)
        baseline_manifest = _read_json(
            baseline_marketplace / ".codex-plugin" / "plugin.json",
            stage,
        )
        if baseline_manifest.get("version") != BASELINE_PLUGIN_VERSION:
            raise LifecycleFailure(stage, "baseline_version_invalid")

        stage = "candidate_prepare"
        candidate_directory = _prepare_candidate(root, candidate, captured_outputs)
        candidate_manifest = _read_json(
            candidate_directory / "release-manifest.json",
            stage,
        )
        plugin_artifacts = [
            artifact
            for artifact in candidate_manifest.get("artifacts", [])
            if isinstance(artifact, dict) and artifact.get("role") == "codex-plugin"
        ]
        if len(plugin_artifacts) != 1:
            raise LifecycleFailure(stage, "candidate_plugin_artifact_invalid")
        plugin_artifact = candidate_directory / str(plugin_artifacts[0]["filename"])
        artifact_sha256 = _sha256(plugin_artifact)
        if artifact_sha256 != plugin_artifacts[0].get("sha256"):
            raise LifecycleFailure(stage, "candidate_plugin_hash_invalid")
        _extract_zip(plugin_artifact, current_marketplace)
        current_plugin_source = current_marketplace / "tooluseproxy"
        current_manifest = _read_json(
            current_plugin_source / ".codex-plugin" / "plugin.json",
            stage,
        )
        current_version = current_manifest.get("version")
        if (
            not isinstance(current_version, str)
            or current_version != candidate_manifest.get("plugin_version")
        ):
            raise LifecycleFailure(stage, "candidate_version_invalid")

        installer = _Installer(
            installation_mode,
            root=root,
            codex_home=codex_home,
            captured_outputs=captured_outputs,
        )

        stage = "baseline_install"
        baseline_root = installer.install(
            baseline_marketplace,
            expected_version=BASELINE_PLUGIN_VERSION,
        )
        baseline_environment = _plugin_environment(
            baseline_root,
            current_data,
            codex_home,
        )
        baseline_cli = baseline_root / "hooks" / "run_cli.sh"
        baseline_hook = baseline_root / "hooks" / "run_hook.sh"
        initialized = _run_plugin_json(
            baseline_cli,
            [
                "init",
                "--codex",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(current_data),
                "--json",
            ],
            cwd=workspace,
            env=baseline_environment,
            stage="baseline_init",
            captured_outputs=captured_outputs,
        )
        if initialized.get("version") != BASELINE_PYTHON_VERSION:
            raise LifecycleFailure("baseline_init", "baseline_python_version_invalid")
        _run_hook(
            baseline_hook,
            _pre_tool_payload(workspace, "baseline-event"),
            cwd=workspace,
            env=baseline_environment,
            stage="baseline_event",
            captured_outputs=captured_outputs,
        )
        database = current_data / "events.db"
        if _schema_version(database) != BASELINE_SCHEMA_VERSION:
            raise LifecycleFailure("baseline_event", "baseline_schema_invalid")
        if "baseline-event" not in _event_tool_use_ids(database):
            raise LifecycleFailure("baseline_event", "baseline_event_missing")

        stage = "baseline_remove"
        installer.disable()
        if baseline_root.exists() or not database.is_file():
            raise LifecycleFailure(stage, "baseline_disable_contract_invalid")
        installer.remove_marketplace()

        stage = "current_install"
        current_root = installer.install(
            current_marketplace,
            expected_version=current_version,
        )
        current_environment = _plugin_environment(
            current_root,
            current_data,
            codex_home,
        )
        current_cli = current_root / "hooks" / "run_cli.sh"
        current_hook = current_root / "hooks" / "run_hook.sh"
        events_before_hook = _event_tool_use_ids(database)
        _run_hook(
            current_hook,
            _pre_tool_payload(workspace, "pre-upgrade-hook"),
            cwd=workspace,
            env=current_environment,
            stage="pre_upgrade_hook",
            captured_outputs=captured_outputs,
        )
        if (
            _schema_version(database) != BASELINE_SCHEMA_VERSION
            or _event_tool_use_ids(database) != events_before_hook
        ):
            raise LifecycleFailure("pre_upgrade_hook", "hook_migrated_database")

        stage = "upgrade_init"
        upgraded = _run_plugin_json(
            current_cli,
            [
                "init",
                "--codex",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(current_data),
                "--json",
            ],
            cwd=workspace,
            env=current_environment,
            stage=stage,
            captured_outputs=captured_outputs,
        )
        backup_value = upgraded.get("migration_backup")
        if not isinstance(backup_value, str):
            raise LifecycleFailure(stage, "migration_backup_missing")
        migration_backup = Path(backup_value)
        if (
            not migration_backup.is_file()
            or _schema_version(migration_backup) != BASELINE_SCHEMA_VERSION
        ):
            raise LifecycleFailure(stage, "migration_backup_invalid")
        current_schema_version = _schema_version(database)
        if current_schema_version <= BASELINE_SCHEMA_VERSION:
            raise LifecycleFailure(stage, "database_not_upgraded")
        if "baseline-event" not in _event_tool_use_ids(database):
            raise LifecycleFailure(stage, "upgrade_lost_baseline_data")
        status = _run_plugin_json(
            current_cli,
            [
                "status",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(current_data),
                "--json",
            ],
            cwd=workspace,
            env=current_environment,
            stage="upgrade_status",
            captured_outputs=captured_outputs,
        )
        if status.get("status") != "active":
            raise LifecycleFailure("upgrade_status", "upgraded_runtime_inactive")
        _run_hook(
            current_hook,
            _pre_tool_payload(workspace, "current-event"),
            cwd=workspace,
            env=current_environment,
            stage="current_event",
            captured_outputs=captured_outputs,
        )
        if "current-event" not in _event_tool_use_ids(database):
            raise LifecycleFailure("current_event", "current_event_missing")

        stage = "current_remove"
        installer.disable()
        if current_root.exists() or not database.is_file():
            raise LifecycleFailure(stage, "current_disable_contract_invalid")
        installer.remove_marketplace()

        stage = "rollback_install"
        rollback_root = installer.install(
            baseline_marketplace,
            expected_version=BASELINE_PLUGIN_VERSION,
        )
        incompatible_environment = _plugin_environment(
            rollback_root,
            current_data,
            codex_home,
        )
        rollback_cli = rollback_root / "hooks" / "run_cli.sh"
        incompatible = _run_command(
            [
                "sh",
                str(rollback_cli),
                "status",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(current_data),
                "--json",
            ],
            cwd=workspace,
            env=incompatible_environment,
            stage="rollback_newer_schema",
            captured_outputs=captured_outputs,
            expected_returncodes=(1,),
        )
        incompatible_payload = _parse_json(incompatible.stdout, "rollback_newer_schema")
        if (
            incompatible_payload.get("status") != "inactive"
            or _schema_version(database) != current_schema_version
        ):
            raise LifecycleFailure(
                "rollback_newer_schema",
                "newer_schema_not_rejected",
            )

        rollback_environment = _plugin_environment(
            rollback_root,
            rollback_data,
            codex_home,
        )
        restored = _run_plugin_json(
            rollback_cli,
            [
                "init",
                "--codex",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(rollback_data),
                "--import-db",
                str(migration_backup),
                "--json",
            ],
            cwd=workspace,
            env=rollback_environment,
            stage="rollback_restore",
            captured_outputs=captured_outputs,
        )
        rollback_database = rollback_data / "events.db"
        rollback_events = _event_tool_use_ids(rollback_database)
        if (
            restored.get("version") != BASELINE_PYTHON_VERSION
            or _schema_version(rollback_database) != BASELINE_SCHEMA_VERSION
            or "baseline-event" not in rollback_events
            or "current-event" in rollback_events
        ):
            raise LifecycleFailure("rollback_restore", "rollback_restore_invalid")
        rollback_status = _run_plugin_json(
            rollback_cli,
            [
                "status",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(rollback_data),
                "--json",
            ],
            cwd=workspace,
            env=rollback_environment,
            stage="rollback_status",
            captured_outputs=captured_outputs,
        )
        if rollback_status.get("status") != "active":
            raise LifecycleFailure("rollback_status", "rollback_runtime_inactive")

        stage = "rollback_remove"
        installer.disable()
        if rollback_root.exists() or not rollback_database.is_file():
            raise LifecycleFailure(stage, "rollback_disable_contract_invalid")
        installer.remove_marketplace()

        cleanup_environment = _plugin_environment(
            current_plugin_source,
            current_data,
            codex_home,
        )
        cleanup_cli = current_plugin_source / "hooks" / "run_cli.sh"
        _delete_managed_data(
            cleanup_cli,
            current_data,
            workspace=workspace,
            environment=cleanup_environment,
            captured_outputs=captured_outputs,
            stage_prefix="current_cleanup",
        )
        cleanup_environment["PLUGIN_DATA"] = str(rollback_data)
        _delete_managed_data(
            cleanup_cli,
            rollback_data,
            workspace=workspace,
            environment=cleanup_environment,
            captured_outputs=captured_outputs,
            stage_prefix="rollback_cleanup",
        )
        if current_data.exists() or rollback_data.exists():
            raise LifecycleFailure("cleanup", "managed_data_remains")
        _assert_no_marker_exposure(captured_outputs)

        return {
            "schema_version": 1,
            "status": "passed",
            "installation_mode": installation_mode,
            "baseline": {
                "commit": BASELINE_COMMIT,
                "plugin_version": BASELINE_PLUGIN_VERSION,
                "schema_version": BASELINE_SCHEMA_VERSION,
            },
            "candidate": {
                "source_commit": candidate_manifest["source"]["commit"],
                "plugin_version": current_version,
                "artifact_sha256": artifact_sha256,
                "schema_version": current_schema_version,
            },
            "trust_review": "manual_required_not_bypassed",
            "checks": {
                "baseline_installed": True,
                "baseline_event_recorded": True,
                "plugin_disabled_before_marketplace_remove": True,
                "marketplace_removed": True,
                "code_removed_between_transitions": True,
                "data_retained_after_remove": True,
                "upgrade_hook_did_not_migrate": True,
                "upgrade_backup_created": True,
                "upgrade_data_preserved": True,
                "upgraded_runtime_active": True,
                "newer_schema_rollback_rejected": True,
                "rollback_backup_imported": True,
                "rollback_baseline_data_preserved": True,
                "post_backup_data_excluded_from_rollback": True,
                "rollback_runtime_active": True,
                "managed_data_deleted_after_confirmation": True,
                "raw_value_exposure": False,
            },
            "metrics": {"external_side_effect_count": 0},
        }


class _Installer:
    def __init__(
        self,
        mode: str,
        *,
        root: Path,
        codex_home: Path,
        captured_outputs: list[str],
    ) -> None:
        self.mode = mode
        self.root = root
        self.environment = {**os.environ, "CODEX_HOME": str(codex_home)}
        self.captured_outputs = captured_outputs
        self.codex = shutil.which("codex") if mode == "codex" else None
        if mode == "codex" and self.codex is None:
            raise LifecycleFailure("prepare", "codex_cli_missing")
        self.installed_root: Path | None = None
        self.marketplace_added = False
        self.transition = 0

    def install(self, marketplace: Path, *, expected_version: str) -> Path:
        if self.installed_root is not None:
            raise LifecycleFailure("install", "previous_plugin_still_installed")
        if self.marketplace_added:
            raise LifecycleFailure("install", "previous_marketplace_still_added")
        self.transition += 1
        if self.mode == "codex":
            assert self.codex is not None
            _run_command(
                [
                    self.codex,
                    "plugin",
                    "marketplace",
                    "add",
                    str(marketplace),
                    "--json",
                ],
                env=self.environment,
                stage="marketplace_add",
                captured_outputs=self.captured_outputs,
            )
            self.marketplace_added = True
            installed = _run_json_command(
                [
                    self.codex,
                    "plugin",
                    "add",
                    "tooluseproxy@tooluseproxy",
                    "--json",
                ],
                env=self.environment,
                stage="plugin_install",
                captured_outputs=self.captured_outputs,
            )
            installed_path = installed.get("installedPath")
            if not isinstance(installed_path, str):
                raise LifecycleFailure("plugin_install", "installed_path_missing")
            plugin_root = Path(installed_path)
        else:
            self.marketplace_added = True
            marketplace_payload = _read_json(
                marketplace / ".agents" / "plugins" / "marketplace.json",
                "plugin_install",
            )
            try:
                relative_source = marketplace_payload["plugins"][0]["source"]["path"]
            except (KeyError, IndexError, TypeError) as error:
                raise LifecycleFailure(
                    "plugin_install",
                    "marketplace_source_invalid",
                ) from error
            source = (marketplace / str(relative_source)).resolve()
            plugin_root = self.root / f"installed-{self.transition}"
            shutil.copytree(source, plugin_root)
        manifest = _read_json(
            plugin_root / ".codex-plugin" / "plugin.json",
            "plugin_install",
        )
        if manifest.get("version") != expected_version:
            raise LifecycleFailure("plugin_install", "installed_version_invalid")
        self.installed_root = plugin_root
        return plugin_root

    def disable(self) -> None:
        if self.installed_root is None:
            raise LifecycleFailure("disable", "plugin_not_installed")
        if self.mode == "codex":
            assert self.codex is not None
            _run_command(
                [
                    self.codex,
                    "plugin",
                    "remove",
                    "tooluseproxy@tooluseproxy",
                    "--json",
                ],
                env=self.environment,
                stage="plugin_remove",
                captured_outputs=self.captured_outputs,
            )
        else:
            shutil.rmtree(self.installed_root)
        if self.installed_root.exists():
            raise LifecycleFailure("disable", "plugin_code_remains")
        self.installed_root = None

    def remove_marketplace(self) -> None:
        if self.installed_root is not None:
            raise LifecycleFailure("marketplace_remove", "plugin_still_installed")
        if not self.marketplace_added:
            raise LifecycleFailure("marketplace_remove", "marketplace_not_added")
        if self.mode == "codex":
            assert self.codex is not None
            _run_command(
                [
                    self.codex,
                    "plugin",
                    "marketplace",
                    "remove",
                    "tooluseproxy",
                    "--json",
                ],
                env=self.environment,
                stage="marketplace_remove",
                captured_outputs=self.captured_outputs,
            )
        self.marketplace_added = False


def _prepare_candidate(
    root: Path,
    candidate: Path | None,
    captured_outputs: list[str],
) -> Path:
    if candidate is None:
        candidate_directory = root / "release-candidate"
        _run_command(
            [
                sys.executable,
                str(RELEASE_BUILDER),
                "--outdir",
                str(candidate_directory),
            ],
            cwd=REPO_ROOT,
            stage="candidate_build",
            captured_outputs=captured_outputs,
        )
    else:
        candidate_directory = candidate.expanduser().resolve()
    _run_command(
        [
            sys.executable,
            str(RELEASE_BUILDER),
            "--verify",
            str(candidate_directory),
        ],
        cwd=REPO_ROOT,
        stage="candidate_verify",
        captured_outputs=captured_outputs,
    )
    return candidate_directory


def _plugin_environment(
    plugin_root: Path,
    data_dir: Path,
    codex_home: Path,
) -> dict[str, str]:
    environment = {
        **os.environ,
        "CODEX_HOME": str(codex_home),
        "PLUGIN_ROOT": str(plugin_root),
        "PLUGIN_DATA": str(data_dir),
        "TOOLUSEPROXY_PYTHON": sys.executable,
    }
    environment.pop("PYTHONPATH", None)
    return environment


def _delete_managed_data(
    launcher: Path,
    data_dir: Path,
    *,
    workspace: Path,
    environment: dict[str, str],
    captured_outputs: list[str],
    stage_prefix: str,
) -> None:
    plan = _run_plugin_json(
        launcher,
        ["uninstall", "plan", "--data-dir", str(data_dir), "--json"],
        cwd=workspace,
        env=environment,
        stage=f"{stage_prefix}_plan",
        captured_outputs=captured_outputs,
    )
    token = plan.get("confirmation_token")
    if plan.get("status") != "review_required" or not isinstance(token, str):
        raise LifecycleFailure(stage_prefix, "uninstall_plan_invalid")
    result = _run_plugin_json(
        launcher,
        [
            "uninstall",
            "apply",
            "--data-dir",
            str(data_dir),
            "--confirmation-token",
            token,
            "--json",
        ],
        cwd=workspace,
        env=environment,
        stage=f"{stage_prefix}_apply",
        captured_outputs=captured_outputs,
    )
    if result.get("status") != "deleted":
        raise LifecycleFailure(stage_prefix, "uninstall_apply_invalid")


def _run_plugin_json(
    launcher: Path,
    arguments: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stage: str,
    captured_outputs: list[str],
) -> dict[str, Any]:
    return _run_json_command(
        ["sh", str(launcher), *arguments],
        cwd=cwd,
        env=env,
        stage=stage,
        captured_outputs=captured_outputs,
    )


def _run_hook(
    launcher: Path,
    payload: dict[str, Any],
    *,
    cwd: Path,
    env: dict[str, str],
    stage: str,
    captured_outputs: list[str],
) -> None:
    _run_command(
        ["sh", str(launcher), "pre-tool-use"],
        cwd=cwd,
        env=env,
        input_text=json.dumps(payload),
        stage=stage,
        captured_outputs=captured_outputs,
    )


def _run_json_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stage: str,
    captured_outputs: list[str],
) -> dict[str, Any]:
    result = _run_command(
        command,
        cwd=cwd,
        env=env,
        stage=stage,
        captured_outputs=captured_outputs,
    )
    return _parse_json(result.stdout, stage)


def _run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    stage: str,
    captured_outputs: list[str],
    expected_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    captured_outputs.extend((result.stdout, result.stderr))
    if result.returncode not in expected_returncodes:
        raise LifecycleFailure(stage, "command_failed")
    return result


def _parse_json(value: str, stage: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as error:
        raise LifecycleFailure(stage, "json_output_invalid") from error
    if not isinstance(payload, dict):
        raise LifecycleFailure(stage, "json_object_required")
    return payload


def _read_json(path: Path, stage: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleFailure(stage, "metadata_invalid") from error
    if not isinstance(payload, dict):
        raise LifecycleFailure(stage, "metadata_object_required")
    return payload


def _pre_tool_payload(workspace: Path, tool_use_id: str) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "lifecycle-session",
        "turn_id": f"{tool_use_id}-turn",
        "tool_use_id": tool_use_id,
        "tool_name": "Bash",
        "tool_input": {"command": f"printf '{SYNTHETIC_MARKER}'"},
        "cwd": str(workspace),
    }


def _schema_version(database: Path) -> int:
    try:
        uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
    except (OSError, sqlite3.Error) as error:
        raise LifecycleFailure("database", "schema_read_failed") from error
    if row is None:
        raise LifecycleFailure("database", "schema_version_missing")
    return int(row[0])


def _event_tool_use_ids(database: Path) -> set[str]:
    try:
        uri = f"{database.resolve(strict=True).as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            rows = connection.execute(
                "SELECT tool_use_id FROM events WHERE tool_use_id IS NOT NULL"
            ).fetchall()
    except (OSError, sqlite3.Error) as error:
        raise LifecycleFailure("database", "event_read_failed") from error
    return {str(row[0]) for row in rows}


def _extract_git_archive(
    commit: str,
    destination: Path,
    captured_outputs: list[str],
) -> None:
    result = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    captured_outputs.append(result.stderr.decode("utf-8", errors="replace"))
    if result.returncode != 0:
        raise LifecycleFailure("baseline_extract", "baseline_commit_unavailable")
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            relative = _safe_relative_path(member.name, "baseline_extract")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise LifecycleFailure("baseline_extract", "archive_type_invalid")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise LifecycleFailure("baseline_extract", "archive_file_unreadable")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())
            target.chmod(member.mode & 0o777)


def _extract_zip(artifact: Path, destination: Path) -> None:
    destination.mkdir()
    try:
        with zipfile.ZipFile(artifact) as archive:
            for info in archive.infolist():
                relative = _safe_relative_path(info.filename, "candidate_extract")
                target = destination.joinpath(*relative.parts)
                mode = info.external_attr >> 16
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if mode and not (mode & 0o100000):
                    raise LifecycleFailure(
                        "candidate_extract",
                        "archive_type_invalid",
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))
                if mode:
                    target.chmod(mode & 0o777)
    except (OSError, zipfile.BadZipFile) as error:
        raise LifecycleFailure("candidate_extract", "archive_invalid") from error


def _safe_relative_path(value: str, stage: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise LifecycleFailure(stage, "archive_path_invalid")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _assert_no_marker_exposure(outputs: list[str]) -> None:
    if any(SYNTHETIC_MARKER in output for output in outputs):
        raise LifecycleFailure("privacy", "raw_value_exposure")


if __name__ == "__main__":
    raise SystemExit(main())
