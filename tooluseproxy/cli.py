from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Sequence

from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.source_config import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    LEGACY_MANIFEST_SCHEMA_VERSION,
    SourceConfigError,
)
from hook_monitor.runtime.models import (
    ProtectedSourceCandidate as StoredProtectedSourceCandidate,
)
from hook_monitor.runtime.storage import (
    CURRENT_SCHEMA_VERSION,
    EventStore,
    ProtectedSourceCandidateStateError,
    SchemaCompatibilityError,
)
from hook_monitor.runtime.workspace import WorkspaceContext, resolve_workspace
from tooluseproxy import __version__
from tooluseproxy.integrations.codex import CODEX_HOOK_PHASES, run_codex_hook
from tooluseproxy.paths import (
    PathConfigurationError,
    RuntimePaths,
    prepare_data_directory,
    resolve_runtime_paths,
    secure_database_permissions,
)
from tooluseproxy.protected_sources import (
    DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS,
    DETECTOR_VERSION,
    LEGACY_DETECTOR_VERSION,
    MAX_MANIFEST_SOURCES,
    MAX_PROTECTED_FILE_BYTES,
    ProtectedSourceCandidate,
    ProtectedSourceScanResult,
    ProtectedSourceWorkspaceLock,
    ProtectedSourceRegistrationError,
    approve_protected_source,
    apply_protected_source_manifest_migration,
    ignore_protected_source_candidate,
    lock_protected_source_workspace,
    plan_protected_source_manifest_migration,
    reject_protected_source_candidate,
    scan_protected_sources,
    suggest_protected_source,
)


MANIFEST_FILENAME = "protected_sources.json"
PROTECT_OUTPUT_SCHEMA_VERSION = 1


class _ProtectCliError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    if raw_arguments and raw_arguments[0] == "trace":
        try:
            return _run_trace(raw_arguments[1:])
        except (
            OSError,
            SchemaCompatibilityError,
            SourceConfigError,
            sqlite3.Error,
            ValueError,
        ) as exc:
            print(f"tooluseproxy: {exc}", file=sys.stderr)
            return 1
    parser = _build_parser()
    args = parser.parse_args(raw_arguments)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "hook":
            return run_codex_hook(
                args.phase,
                db_path=args.db,
                data_dir=args.data_dir,
            )
        if args.command == "init":
            return _run_init(args)
        if args.command == "doctor":
            return _run_doctor(args)
        if args.command == "status":
            return _run_status(args)
        if args.command == "protect":
            return _run_protect(args)
        if args.command == "trace":
            return _run_trace(args.arguments)
    except (
        OSError,
        PathConfigurationError,
        SchemaCompatibilityError,
        SourceConfigError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        print(f"tooluseproxy: {exc}", file=sys.stderr)
        return 1
    parser.error(f"unsupported command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tooluseproxy",
        description="Inspect and guard local information flow in Codex tool use.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    hook = subparsers.add_parser("hook", help="Run an internal Codex lifecycle hook.")
    hook.add_argument("phase", choices=tuple(CODEX_HOOK_PHASES))
    _add_runtime_path_arguments(hook)

    init = subparsers.add_parser("init", help="Initialize local state and a workspace manifest.")
    init.add_argument("--codex", action="store_true", help="Initialize the Codex integration.")
    init.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Workspace root. Defaults to the current directory.",
    )
    init.add_argument(
        "--import-db",
        type=Path,
        help="Import an existing SQLite database with the SQLite backup API.",
    )
    init.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(init)

    doctor = subparsers.add_parser("doctor", help="Diagnose installation and workspace state.")
    doctor.add_argument("--workspace", type=Path, default=Path.cwd())
    doctor.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(doctor)

    status = subparsers.add_parser("status", help="Show current runtime status.")
    status.add_argument("--workspace", type=Path, default=Path.cwd())
    status.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(status)

    protect = subparsers.add_parser(
        "protect",
        help="Plan and explicitly approve protected source manifest changes.",
    )
    protect_subparsers = protect.add_subparsers(dest="protect_command", required=True)

    suggest = protect_subparsers.add_parser(
        "suggest",
        help="Inspect explicit local paths and create value-free proposals.",
    )
    suggest.add_argument(
        "--path",
        required=True,
        help="One workspace-relative .env or JSON path.",
    )
    suggest.add_argument("--workspace", type=Path, default=Path.cwd())
    suggest.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(suggest)

    scan = protect_subparsers.add_parser(
        "scan",
        help="Discover one value-free proposal with a bounded offline workspace scan.",
    )
    scan.add_argument("--workspace", type=Path, default=Path.cwd())
    scan.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(scan)

    approve = protect_subparsers.add_parser(
        "approve",
        help=(
            "Approve one saved proposal with revision and expected-manifest "
            "precondition checks."
        ),
    )
    approve.add_argument("candidate_id")
    approve.add_argument("--candidate-revision", required=True)
    approve.add_argument("--expected-manifest-sha256", required=True)
    approve.add_argument("--workspace", type=Path, default=Path.cwd())
    approve.add_argument("--json", action="store_true", help="Print machine-readable output.")
    _add_runtime_path_arguments(approve)

    for decision in ("reject", "ignore"):
        decision_parser = protect_subparsers.add_parser(
            decision,
            help=f"{decision.capitalize()} one saved proposal without changing the manifest.",
        )
        decision_parser.add_argument("candidate_id")
        decision_parser.add_argument("--candidate-revision", required=True)
        decision_parser.add_argument("--workspace", type=Path, default=Path.cwd())
        decision_parser.add_argument(
            "--json",
            action="store_true",
            help="Print machine-readable output.",
        )
        _add_runtime_path_arguments(decision_parser)

    migrate = protect_subparsers.add_parser(
        "migrate",
        help="Plan or explicitly apply a protected source manifest migration.",
    )
    migrate_subparsers = migrate.add_subparsers(
        dest="migration_command",
        required=True,
    )
    migration_plan = migrate_subparsers.add_parser(
        "plan",
        help="Create a value-free schema v1 to v2 migration plan.",
    )
    migration_plan.add_argument("--workspace", type=Path, default=Path.cwd())
    migration_plan.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable output.",
    )
    _add_runtime_path_arguments(migration_plan)

    migration_apply = migrate_subparsers.add_parser(
        "apply",
        help="Apply one explicitly reviewed manifest migration plan.",
    )
    migration_apply.add_argument("--migration-revision", required=True)
    migration_apply.add_argument("--expected-manifest-sha256", required=True)
    migration_apply.add_argument("--workspace", type=Path, default=Path.cwd())
    migration_apply.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable output.",
    )
    _add_runtime_path_arguments(migration_apply)

    trace = subparsers.add_parser("trace", help="Show source lineage for a stored analysis run.")
    trace.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser


def _add_runtime_path_arguments(parser: argparse.ArgumentParser) -> None:
    paths = parser.add_mutually_exclusive_group()
    paths.add_argument("--db", type=Path, help="Use an explicit SQLite database path.")
    paths.add_argument("--data-dir", type=Path, help="Use an explicit writable data directory.")


def _run_init(args: argparse.Namespace) -> int:
    paths = resolve_runtime_paths(db_path=args.db, data_dir=args.data_dir)
    if args.codex and paths.source == "platform_default":
        raise ValueError(
            "Codex Plugin data directory is unknown; use the setup command "
            "printed by the Plugin Hook or pass --data-dir explicitly"
        )
    plugin_data = os.environ.get("PLUGIN_DATA")
    if args.codex and plugin_data:
        plugin_paths = resolve_runtime_paths(data_dir=plugin_data)
        if paths.db_path != plugin_paths.db_path:
            raise ValueError(
                "--data-dir does not match the Codex Plugin PLUGIN_DATA directory"
            )
    prepare_data_directory(paths)
    secure_database_permissions(paths.db_path)
    if args.import_db is not None:
        _import_database(args.import_db, paths.db_path)

    backup_path = (
        None
        if args.import_db is not None
        else _backup_database_before_upgrade(paths.db_path)
    )

    if not paths.db_path.exists():
        _create_secure_empty_file(paths.db_path)
    store = EventStore(paths.db_path)
    store.initialize()
    secure_database_permissions(paths.db_path)

    workspace = resolve_workspace(
        str(args.workspace),
        str(args.workspace),
        discovered_by="init",
    )
    if not workspace.ready or workspace.canonical_root is None:
        raise ValueError(f"workspace is not usable: {workspace.status}")
    store.register_workspace(workspace)

    manifest_path = Path(workspace.canonical_root) / MANIFEST_FILENAME
    manifest_created = _create_empty_manifest(manifest_path)
    payload = {
        "status": "initialized",
        "version": __version__,
        "codex": bool(args.codex),
        "data_dir": str(paths.data_dir),
        "db_path": str(paths.db_path),
        "path_source": paths.source,
        "workspace_id": workspace.workspace_id,
        "workspace_root": workspace.canonical_root,
        "manifest_path": str(manifest_path),
        "manifest_created": manifest_created,
        "migration_backup": None if backup_path is None else str(backup_path),
    }
    _render(payload, as_json=args.json)
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    paths = resolve_runtime_paths(db_path=args.db, data_dir=args.data_dir)
    workspace, workspace_path = _resolve_cli_workspace(args.workspace)
    checks: list[dict[str, Any]] = []

    checks.append(
        _check(
            "workspace",
            workspace.ready,
            (
                str(workspace_path)
                if workspace.ready
                else f"workspace is not usable: {workspace.status}"
            ),
        )
    )
    checks.append(
        _check(
            "data_directory",
            paths.data_dir.is_dir() and os.access(paths.data_dir, os.W_OK),
            str(paths.data_dir),
        )
    )
    permissions_ok, permissions_detail = _inspect_data_directory_permissions(
        paths.data_dir
    )
    checks.append(
        _check(
            "data_directory_permissions",
            permissions_ok,
            permissions_detail,
        )
    )
    summary = _read_database_summary(paths.db_path)
    checks.append(_check("database", summary["ok"], summary["detail"]))
    registration_ok, registration_detail = _inspect_workspace_registration(
        paths.db_path,
        workspace,
    )
    checks.append(
        _check(
            "workspace_registration",
            registration_ok,
            registration_detail,
        )
    )

    manifest_path = workspace_path / MANIFEST_FILENAME
    protected_sources = _inspect_manifest(manifest_path)
    checks.append(
        _check(
            "protected_sources",
            bool(protected_sources["runtime_readable"]),
            str(protected_sources["detail"]),
        )
    )

    plugin_root = os.environ.get("PLUGIN_ROOT")
    plugin_data = os.environ.get("PLUGIN_DATA")
    if plugin_root is not None or plugin_data is not None:
        plugin_root_path = None if not plugin_root else _absolute_path(plugin_root)
        plugin_data_path = None if not plugin_data else _absolute_path(plugin_data)
        plugin_ok = bool(
            plugin_root_path
            and plugin_data_path
            and (plugin_root_path / ".codex-plugin" / "plugin.json").is_file()
            and (plugin_root_path / "hooks" / "hooks.json").is_file()
            and plugin_data_path == paths.data_dir
        )
        checks.append(
            _check(
                "plugin_environment",
                plugin_ok,
                (
                    f"PLUGIN_ROOT={plugin_root or '-'} "
                    f"PLUGIN_DATA={plugin_data or '-'} "
                    f"resolved_data_dir={paths.data_dir}"
                ),
            )
        )

    ok = all(bool(item["ok"]) for item in checks)
    payload = {
        "status": "ok" if ok else "needs_attention",
        "version": __version__,
        "path_source": paths.source,
        "db_path": str(paths.db_path),
        "workspace_id": workspace.workspace_id,
        "workspace_root": str(workspace_path),
        "checks": checks,
        "protected_sources": protected_sources,
    }
    _render(payload, as_json=args.json)
    return 0 if ok else 1


def _run_status(args: argparse.Namespace) -> int:
    paths = resolve_runtime_paths(db_path=args.db, data_dir=args.data_dir)
    summary = _read_database_summary(paths.db_path)
    workspace, workspace_path = _resolve_cli_workspace(args.workspace)
    registration_ok, registration_detail = _inspect_workspace_registration(
        paths.db_path,
        workspace,
    )
    protected_sources = _inspect_manifest(workspace_path / MANIFEST_FILENAME)
    payload = {
        "status": (
            "active"
            if (
                workspace.ready
                and summary["ok"]
                and registration_ok
                and protected_sources["runtime_readable"]
            )
            else "inactive"
        ),
        "version": __version__,
        "path_source": paths.source,
        "db_path": str(paths.db_path),
        "database": summary,
        "workspace_id": workspace.workspace_id,
        "workspace_root": str(workspace_path),
        "workspace_registration": {
            "ok": registration_ok,
            "detail": registration_detail,
        },
        "protected_sources": protected_sources,
    }
    _render(payload, as_json=args.json)
    return 0 if payload["status"] == "active" else 1


def _run_protect(args: argparse.Namespace) -> int:
    try:
        store, workspace, workspace_path, paths = _resolve_protect_context(args)
        if args.protect_command == "suggest":
            payload = _suggest_protected_sources(
                store,
                workspace,
                workspace_path,
                (args.path,),
            )
        elif args.protect_command == "scan":
            payload = _scan_protected_source_candidates(
                store,
                workspace,
                workspace_path,
                paths,
            )
        elif args.protect_command == "approve":
            payload = _approve_protected_source_candidate(
                store,
                workspace,
                workspace_path,
                candidate_id=args.candidate_id,
                candidate_revision=args.candidate_revision,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
        elif args.protect_command in {"reject", "ignore"}:
            payload = _review_protected_source_candidate(
                store,
                workspace,
                candidate_id=args.candidate_id,
                candidate_revision=args.candidate_revision,
                decision=args.protect_command,
            )
        elif args.protect_command == "migrate":
            assert workspace.workspace_id is not None
            if args.migration_command == "plan":
                migration = plan_protected_source_manifest_migration(
                    workspace_path,
                    workspace_id=workspace.workspace_id,
                    backup_root=paths.data_dir,
                )
            else:
                migration = apply_protected_source_manifest_migration(
                    workspace_path,
                    workspace_id=workspace.workspace_id,
                    migration_revision=args.migration_revision,
                    expected_manifest_sha256=args.expected_manifest_sha256,
                    backup_root=paths.data_dir,
                )
            payload = migration.to_public_payload()
        else:  # pragma: no cover - argparse constrains this branch
            raise _ProtectCliError(
                "unsupported_protect_command",
                "protected source command is not supported",
            )
    except (
        ProtectedSourceCandidateStateError,
        ProtectedSourceRegistrationError,
        _ProtectCliError,
    ) as exc:
        _render_protect_error(exc.code, str(exc), as_json=args.json)
        return 1
    except (OSError, PathConfigurationError, SchemaCompatibilityError, sqlite3.Error):
        _render_protect_error(
            "state_unavailable",
            "protected source state is unavailable",
            as_json=args.json,
        )
        return 1
    except ValueError:
        migration_command = args.protect_command == "migrate"
        scan_command = args.protect_command == "scan"
        _render_protect_error(
            (
                "migration_state_conflict"
                if migration_command
                else "candidate_state_conflict"
            ),
            (
                "protected source manifest changed; create a new migration plan"
                if migration_command
                else (
                    "protected source candidate state changed; run scan again"
                    if scan_command
                    else "protected source candidate state changed; run suggest again"
                )
            ),
            as_json=args.json,
        )
        return 1

    _render_protect_payload(payload, as_json=args.json)
    return 0


def _resolve_protect_context(
    args: argparse.Namespace,
) -> tuple[EventStore, WorkspaceContext, Path, RuntimePaths]:
    paths = resolve_runtime_paths(db_path=args.db, data_dir=args.data_dir)
    workspace, workspace_path = _resolve_cli_workspace(args.workspace)
    if (
        not workspace.ready
        or workspace.workspace_id is None
        or workspace.canonical_root is None
    ):
        raise _ProtectCliError(
            "workspace_unavailable",
            "workspace is not usable for protected source registration",
        )
    store = EventStore(paths.db_path)
    try:
        store.require_runtime_schema()
    except SchemaCompatibilityError as exc:
        raise _ProtectCliError(
            exc.code,
            "database requires tooluseproxy init before protected source registration",
        ) from None
    registration_ok, _ = _inspect_workspace_registration(paths.db_path, workspace)
    if not registration_ok:
        raise _ProtectCliError(
            "workspace_not_registered",
            "workspace is not registered; run tooluseproxy init first",
        )
    return store, workspace, workspace_path, paths


def _suggest_protected_sources(
    store: EventStore,
    workspace: WorkspaceContext,
    workspace_path: Path,
    relative_paths: tuple[str, ...],
) -> dict[str, Any]:
    with lock_protected_source_workspace(workspace_path) as workspace_lock:
        return _suggest_protected_sources_under_lock(
            store,
            workspace,
            workspace_path,
            relative_paths,
            workspace_lock=workspace_lock,
        )


def _scan_protected_source_candidates(
    store: EventStore,
    workspace: WorkspaceContext,
    workspace_path: Path,
    paths: RuntimePaths,
) -> dict[str, Any]:
    assert workspace.workspace_id is not None
    with lock_protected_source_workspace(workspace_path) as workspace_lock:
        scan = scan_protected_sources(
            workspace_path,
            workspace_id=workspace.workspace_id,
            workspace_lock=workspace_lock,
            excluded_relative_paths=_scan_excluded_relative_paths(
                workspace_path,
                paths,
            ),
        )
        return _save_next_scanned_candidate(
            store,
            workspace,
            scan,
        )


def _save_next_scanned_candidate(
    store: EventStore,
    workspace: WorkspaceContext,
    scan: ProtectedSourceScanResult,
) -> dict[str, Any]:
    """Persist and expose at most one candidate from one bounded scan."""

    assert workspace.workspace_id is not None
    suppression_fingerprints = tuple(
        candidate.suppression_fingerprint for candidate in scan.candidates
    )
    stored_candidates = (
        store.list_protected_source_candidates_by_suppression_fingerprints(
            workspace.workspace_id,
            suppression_fingerprints,
        )
    )
    stored_by_fingerprint = {
        candidate.suppression_fingerprint: candidate
        for candidate in stored_candidates
    }
    selected: ProtectedSourceCandidate | None = None
    selected_candidate_id: str | None = None
    for candidate in scan.candidates:
        stored = stored_by_fingerprint.get(candidate.suppression_fingerprint)
        if not _scan_candidate_requires_proposal(candidate, stored):
            continue
        created = store.create_or_get_protected_source_candidate(
            **candidate.to_storage_record(discovery_source="bounded_scan")
        )
        if (
            created.suppressed
            or created.already_approved
            or created.approval_in_progress
        ):
            continue
        if (
            created.candidate.candidate_revision_sha256
            != candidate.candidate_revision_sha256
        ):
            raise _ProtectCliError(
                "candidate_state_conflict",
                "protected source candidate changed during scan",
            )
        selected = candidate
        selected_candidate_id = created.candidate.candidate_id
        break

    current_candidates = (
        store.list_protected_source_candidates_by_suppression_fingerprints(
            workspace.workspace_id,
            suppression_fingerprints,
        )
    )
    current_by_fingerprint = {
        candidate.suppression_fingerprint: candidate
        for candidate in current_candidates
    }
    candidates: list[dict[str, object]] = []
    selected_fingerprint: str | None = None
    if selected is not None and selected_candidate_id is not None:
        current = current_by_fingerprint.get(selected.suppression_fingerprint)
        if (
            current is None
            or current.candidate_id != selected_candidate_id
            or current.status != "proposed"
            or current.candidate_revision_sha256
            != selected.candidate_revision_sha256
        ):
            raise _ProtectCliError(
                "candidate_state_conflict",
                "protected source candidate changed during scan",
            )
        candidates.append(
            selected.with_candidate_id(selected_candidate_id).to_public_payload()
        )
        selected_fingerprint = selected.suppression_fingerprint

    suppressed_count = 0
    approved_count = int(scan.already_registered_count)
    approval_in_progress_count = 0
    remaining_candidate_count = 0
    for candidate in scan.candidates:
        if candidate.suppression_fingerprint == selected_fingerprint:
            continue
        stored = current_by_fingerprint.get(candidate.suppression_fingerprint)
        if _scan_candidate_requires_proposal(candidate, stored):
            remaining_candidate_count += 1
        elif stored is not None and stored.status in {"rejected", "ignored"}:
            suppressed_count += 1
        elif stored is not None and stored.status == "approved":
            approved_count += 1
        elif stored is not None and stored.status == "approving":
            approval_in_progress_count += 1

    if candidates:
        status = "review_required"
    elif approval_in_progress_count:
        status = "approval_in_progress"
    elif remaining_candidate_count:
        raise _ProtectCliError(
            "candidate_state_conflict",
            "protected source candidate changed during scan",
        )
    elif not scan.scan_complete:
        status = "scan_incomplete"
    elif suppressed_count:
        status = "suppressed"
    else:
        status = "no_candidate"

    scan_counts = {
        name: int(getattr(scan, name))
        for name in (
            "entries_seen",
            "directories_scanned",
            "files_seen",
            "eligible_files_seen",
            "inspected_bytes",
            "detected_candidate_count",
            "public_candidate_bytes",
        )
    }
    continuation_required = bool(
        candidates
        or remaining_candidate_count
        or approval_in_progress_count
        or not scan.scan_complete
    )
    return {
        "schema_version": PROTECT_OUTPUT_SCHEMA_VERSION,
        "status": status,
        "scanner_version": scan.scanner_version,
        "scan_complete": bool(scan.scan_complete),
        "truncation_reasons": list(scan.truncation_reasons),
        "scan_limits": asdict(DEFAULT_PROTECTED_SOURCE_SCAN_LIMITS),
        "scan_counts": scan_counts,
        "skipped_counts": dict(scan.skipped_counts),
        "manifest_sha256": scan.manifest_sha256,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "suppressed_count": suppressed_count,
        "already_registered_count": approved_count,
        "approval_in_progress_count": approval_in_progress_count,
        "remaining_candidate_count": remaining_candidate_count,
        "continuation_required": continuation_required,
        "approval_mode": "one_at_a_time",
        "rescan_required_after_manifest_change": True,
    }


def _scan_candidate_requires_proposal(
    candidate: ProtectedSourceCandidate,
    stored: StoredProtectedSourceCandidate | None,
) -> bool:
    if stored is None or stored.status in {"proposed", "stale"}:
        return True
    return bool(
        stored.status == "approved"
        and stored.manifest_sha256 != candidate.manifest_sha256
    )


def _scan_excluded_relative_paths(
    workspace_path: Path,
    paths: RuntimePaths,
) -> tuple[str, ...]:
    canonical_workspace = Path(os.path.realpath(workspace_path))
    canonical_data_dir = Path(os.path.realpath(paths.data_dir))
    relative_data_dir = _relative_path_from_filesystem_ancestor(
        canonical_workspace,
        canonical_data_dir,
    )
    if relative_data_dir is None:
        return ()
    if relative_data_dir != Path("."):
        return (relative_data_dir.as_posix(),)

    exclusions = ["manifest-backups"]
    canonical_database = Path(os.path.realpath(paths.db_path))
    relative_database = _relative_path_from_filesystem_ancestor(
        canonical_workspace,
        canonical_database,
    )
    if relative_database is not None and relative_database != Path("."):
        database_path = relative_database.as_posix()
        exclusions.extend(
            (
                database_path,
                f"{database_path}-wal",
                f"{database_path}-shm",
            )
        )
    return tuple(sorted(set(exclusions), key=lambda value: value.encode("utf-8")))


def _relative_path_from_filesystem_ancestor(
    ancestor: Path,
    target: Path,
) -> Path | None:
    """Return a relative path using filesystem identity for existing ancestors."""

    current = target
    suffix: list[str] = []
    while True:
        try:
            if os.path.samefile(ancestor, current):
                return Path(*reversed(suffix)) if suffix else Path(".")
        except OSError:
            pass
        parent = current.parent
        if parent == current:
            return None
        suffix.append(current.name)
        current = parent


def _suggest_protected_sources_under_lock(
    store: EventStore,
    workspace: WorkspaceContext,
    workspace_path: Path,
    relative_paths: tuple[str, ...],
    *,
    workspace_lock: ProtectedSourceWorkspaceLock,
) -> dict[str, Any]:
    assert workspace.workspace_id is not None
    candidates: list[dict[str, object]] = []
    manifest_sha256: str | None = None
    suppressed_count = 0
    already_registered_count = 0
    approval_in_progress_count = 0
    for relative_path in relative_paths:
        try:
            candidate = suggest_protected_source(
                workspace_path,
                relative_path,
                workspace_id=workspace.workspace_id,
            )
        except ProtectedSourceRegistrationError as exc:
            if exc.code == "no_secret_selector":
                continue
            raise
        if manifest_sha256 is None:
            manifest_sha256 = candidate.manifest_sha256
        elif manifest_sha256 != candidate.manifest_sha256:
            raise _ProtectCliError(
                "manifest_changed",
                "protected_sources.json changed during suggestion",
            )
        candidate_storage_record = candidate.to_storage_record(
            discovery_source="explicit_path"
        )
        if candidate.already_registered:
            confirmed = approve_protected_source(
                workspace_path,
                candidate,
                candidate_revision=candidate.candidate_revision,
                expected_manifest_sha256=candidate.manifest_sha256,
                workspace_lock=workspace_lock,
            )
            manifest_sha256 = confirmed.manifest_sha256
            reconcilable = (
                store.select_registered_protected_source_candidate_for_reconcile(
                    workspace.workspace_id,
                    candidate.suppression_fingerprint,
                    proposed_source_json=str(
                        candidate_storage_record["proposed_source_json"]
                    ),
                    approved_source_id=confirmed.source_id,
                )
            )
            if reconcilable is not None:
                store.reconcile_registered_protected_source_candidate(
                    reconcilable.candidate_id,
                    workspace.workspace_id,
                    candidate.suppression_fingerprint,
                    approval_attempt_id=reconcilable.approval_attempt_id,
                    proposed_source_json=str(
                        candidate_storage_record["proposed_source_json"]
                    ),
                    result_manifest_sha256=confirmed.manifest_sha256,
                    approved_source_id=confirmed.source_id,
                )
            already_registered_count += 1
            continue
        created = store.create_or_get_protected_source_candidate(
            **candidate_storage_record
        )
        if created.suppressed:
            suppressed_count += 1
            continue
        if created.already_approved:
            already_registered_count += 1
            continue
        if created.approval_in_progress:
            approval_in_progress_count += 1
            continue
        if (
            created.candidate.candidate_revision_sha256
            != candidate.candidate_revision_sha256
        ):
            raise _ProtectCliError(
                "candidate_state_conflict",
                "protected source candidate changed during suggestion",
            )
        candidate = candidate.with_candidate_id(created.candidate.candidate_id)
        candidates.append(candidate.to_public_payload())

    if candidates:
        status = "review_required"
    elif approval_in_progress_count:
        status = "approval_in_progress"
    elif suppressed_count:
        status = "suppressed"
    else:
        status = "no_candidate"
    return {
        "schema_version": PROTECT_OUTPUT_SCHEMA_VERSION,
        "status": status,
        "scan_complete": True,
        "manifest_sha256": manifest_sha256,
        "candidates": candidates,
        "suppressed_count": suppressed_count,
        "already_registered_count": already_registered_count,
        "approval_in_progress_count": approval_in_progress_count,
    }


def _approve_protected_source_candidate(
    store: EventStore,
    workspace: WorkspaceContext,
    workspace_path: Path,
    *,
    candidate_id: str,
    candidate_revision: str,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    with lock_protected_source_workspace(workspace_path) as workspace_lock:
        return _approve_protected_source_candidate_under_lock(
            store,
            workspace,
            workspace_path,
            candidate_id=candidate_id,
            candidate_revision=candidate_revision,
            expected_manifest_sha256=expected_manifest_sha256,
            workspace_lock=workspace_lock,
        )


def _approve_protected_source_candidate_under_lock(
    store: EventStore,
    workspace: WorkspaceContext,
    workspace_path: Path,
    *,
    candidate_id: str,
    candidate_revision: str,
    expected_manifest_sha256: str,
    workspace_lock: ProtectedSourceWorkspaceLock,
) -> dict[str, object]:
    stored = _load_workspace_candidate(store, workspace, candidate_id)
    _reject_stale_candidate(
        stored,
        allow_legacy_approval_recovery=True,
    )
    _verify_stored_candidate_revision(stored.candidate_revision_sha256, candidate_revision)
    if stored.status not in {"proposed", "approving", "approved"}:
        raise _ProtectCliError(
            "candidate_not_proposed",
            "candidate is not awaiting approval",
        )
    record = asdict(stored)
    if stored.status == "approved":
        result = approve_protected_source(
            workspace_path,
            record,
            candidate_revision=candidate_revision,
            expected_manifest_sha256=expected_manifest_sha256,
            workspace_lock=workspace_lock,
        )
        return result.to_public_payload()

    if stored.status == "approving":
        if (
            stored.manifest_sha256 is None
            or not hmac.compare_digest(
                stored.manifest_sha256,
                expected_manifest_sha256,
            )
        ):
            raise ProtectedSourceRegistrationError("manifest_conflict")
        claimed = stored
    else:
        claimed = store.claim_protected_source_candidate_approval(
            stored.candidate_id,
            expected_revision_sha256=stored.candidate_revision_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
        )
    approval_attempt_id = claimed.approval_attempt_id
    if approval_attempt_id is None:
        raise _ProtectCliError(
            "candidate_state_conflict",
            "candidate approval reservation is invalid",
        )
    record = asdict(claimed)
    try:
        result = approve_protected_source(
            workspace_path,
            record,
            candidate_revision=candidate_revision,
            expected_manifest_sha256=expected_manifest_sha256,
            workspace_lock=workspace_lock,
        )
    except ProtectedSourceRegistrationError as exc:
        if exc.code not in {
            "manifest_durability_unknown",
            "manifest_postcondition_failed",
        }:
            decision_code = {
                "source_changed": "source_changed",
                "manifest_conflict": "manifest_changed",
            }.get(exc.code, "approval_released")
            store.release_protected_source_candidate_approval(
                claimed.candidate_id,
                approval_attempt_id=approval_attempt_id,
                expected_revision_sha256=claimed.candidate_revision_sha256,
                expected_manifest_sha256=claimed.manifest_sha256,
                result_manifest_sha256=None,
                decision_code=decision_code,
            )
        raise

    try:
        store.finalize_protected_source_candidate_approval(
            claimed.candidate_id,
            approval_attempt_id=approval_attempt_id,
            expected_revision_sha256=claimed.candidate_revision_sha256,
            expected_manifest_sha256=claimed.manifest_sha256,
            result_manifest_sha256=result.manifest_sha256,
            approved_source_id=result.source_id,
            decision_code=(
                "approved" if result.status == "approved" else "already_registered"
            ),
        )
    except ProtectedSourceCandidateStateError:
        current = _load_workspace_candidate(store, workspace, claimed.candidate_id)
        if not (
            current.status == "approved"
            and current.approved_source_id == result.source_id
            and current.manifest_sha256 == result.manifest_sha256
        ):
            raise
    return result.to_public_payload()


def _review_protected_source_candidate(
    store: EventStore,
    workspace: WorkspaceContext,
    *,
    candidate_id: str,
    candidate_revision: str,
    decision: str,
) -> dict[str, object]:
    stored = _load_workspace_candidate(store, workspace, candidate_id)
    _reject_stale_candidate(stored)
    if stored.status != "proposed":
        raise _ProtectCliError(
            "candidate_not_proposed",
            "candidate is not awaiting review",
        )
    record = asdict(stored)
    if decision == "reject":
        review = reject_protected_source_candidate(
            record,
            candidate_revision=candidate_revision,
        )
        next_status = "rejected"
    else:
        review = ignore_protected_source_candidate(
            record,
            candidate_revision=candidate_revision,
        )
        next_status = "ignored"
    store.transition_protected_source_candidate(
        stored.candidate_id,
        expected_status="proposed",
        expected_revision_sha256=stored.candidate_revision_sha256,
        to_status=next_status,
        decision_code=next_status,
        authority="cli_explicit",
        expected_manifest_sha256=stored.manifest_sha256,
        result_manifest_sha256=None,
    )
    return review.to_public_payload()


def _reject_stale_candidate(
    candidate: StoredProtectedSourceCandidate,
    *,
    allow_legacy_approval_recovery: bool = False,
) -> None:
    if candidate.detector_version == DETECTOR_VERSION:
        return
    if (
        allow_legacy_approval_recovery
        and candidate.detector_version == LEGACY_DETECTOR_VERSION
        and candidate.status in {"approving", "approved"}
    ):
        return
    raise _ProtectCliError(
        "candidate_detector_stale",
        "candidate detector is stale; run protect scan again",
    )


def _load_workspace_candidate(
    store: EventStore,
    workspace: WorkspaceContext,
    candidate_id: str,
):
    try:
        candidate = store.get_protected_source_candidate(candidate_id)
    except ValueError:
        raise _ProtectCliError(
            "candidate_not_found",
            "protected source candidate was not found",
        ) from None
    if candidate is None or candidate.workspace_id != workspace.workspace_id:
        raise _ProtectCliError(
            "candidate_not_found",
            "protected source candidate was not found",
        )
    return candidate


def _verify_stored_candidate_revision(
    expected_revision_sha256: str,
    candidate_revision: str,
) -> None:
    if (
        not isinstance(candidate_revision, str)
        or not candidate_revision
        or len(candidate_revision) > 256
    ):
        raise ProtectedSourceRegistrationError("candidate_revision_invalid")
    try:
        encoded = candidate_revision.encode("ascii")
    except UnicodeEncodeError:
        raise ProtectedSourceRegistrationError("candidate_revision_invalid") from None
    supplied_sha256 = hashlib.sha256(encoded).hexdigest()
    if not hmac.compare_digest(supplied_sha256, expected_revision_sha256):
        raise ProtectedSourceRegistrationError("candidate_revision_invalid")


def _render_protect_payload(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(f"status: {payload['status']}")
    if payload.get("manifest_sha256") is not None:
        print(f"manifest_sha256: {payload['manifest_sha256']}")
    for key in (
        "scanner_version",
        "scan_complete",
        "truncation_reasons",
        "scan_limits",
        "scan_counts",
        "skipped_counts",
        "candidate_count",
        "suppressed_count",
        "already_registered_count",
        "approval_in_progress_count",
        "remaining_candidate_count",
        "continuation_required",
        "approval_mode",
        "rescan_required_after_manifest_change",
    ):
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        print(f"{key}: {value}")
    for candidate in payload.get("candidates", []):
        print(json.dumps(candidate, ensure_ascii=False, sort_keys=True))
    if "candidate_id" in payload:
        print(f"candidate_id: {payload['candidate_id']}")
    if "source_id" in payload:
        print(f"source_id: {payload['source_id']}")
    for key in (
        "migration_kind",
        "migration_id",
        "migration_revision",
        "result_manifest_sha256",
        "from_schema_version",
        "to_schema_version",
        "schema_version_was_omitted",
        "source_count",
        "sources_field_will_be_added",
        "selector_changes",
        "formatting_policy",
        "backup_relative_path",
        "changes",
        "review_required",
    ):
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        print(f"{key}: {value}")


def _render_protect_error(code: str, message: str, *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "schema_version": PROTECT_OUTPUT_SCHEMA_VERSION,
                    "status": "error",
                    "error": {"code": code, "message": message},
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return
    print(f"tooluseproxy: {code}: {message}", file=sys.stderr)


def _run_trace(arguments: list[str]) -> int:
    from hook_monitor.cli.trace import main as trace_main

    paths = resolve_runtime_paths()
    return trace_main(
        arguments,
        default_db_path=paths.db_path,
        allow_schema_migration=False,
    )


def _import_database(source: Path, destination: Path) -> None:
    source_path = _absolute_path(source)
    destination_path = _absolute_path(destination)
    if source_path == destination_path:
        raise ValueError("source and destination database paths are identical")
    if not source_path.is_file():
        raise ValueError(f"database to import does not exist: {source_path}")
    if destination_path.exists():
        raise ValueError(f"destination database already exists: {destination_path}")

    destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        source_uri = f"{source_path.as_uri()}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source_conn:
            version_row = source_conn.execute("PRAGMA user_version").fetchone()
            source_version = 0 if version_row is None else int(version_row[0])
            if source_version > CURRENT_SCHEMA_VERSION:
                raise ValueError(
                    f"database schema v{source_version} is newer than runtime "
                    f"v{CURRENT_SCHEMA_VERSION}"
                )
            _create_secure_empty_file(destination_path)
            with sqlite3.connect(destination_path) as destination_conn:
                source_conn.backup(destination_conn)
                result = destination_conn.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise sqlite3.DatabaseError("imported database failed quick_check")
    except Exception:
        _remove_sqlite_files(destination_path)
        raise


def _create_empty_manifest(path: Path) -> bool:
    if path.exists():
        load_sources_and_chunks(path.parent, path)
        return False
    payload = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "sources": [],
    }
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            load_sources_and_chunks(path.parent, path)
            return False
    finally:
        temporary_path.unlink(missing_ok=True)
    return True


def _read_database_summary(db_path: Path) -> dict[str, Any]:
    if not db_path.is_file():
        return {"ok": False, "detail": f"database not found: {db_path}", "counts": {}}
    try:
        EventStore(db_path).require_runtime_schema()
    except SchemaCompatibilityError as exc:
        return {
            "ok": False,
            "detail": f"{exc.code}: {exc}",
            "counts": {},
        }
    uri = f"{db_path.as_uri()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True) as conn:
            quick_check = conn.execute("PRAGMA quick_check").fetchone()
            version_row = conn.execute("PRAGMA user_version").fetchone()
            schema_version = 0 if version_row is None else int(version_row[0])
            counts = {
                "workspaces": int(conn.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0]),
                "events": int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
            }
    except sqlite3.Error as exc:
        return {"ok": False, "detail": f"database unreadable: {type(exc).__name__}", "counts": {}}
    if quick_check is None or quick_check[0] != "ok":
        return {
            "ok": False,
            "detail": "database quick_check failed",
            "counts": counts,
            "schema_version": schema_version,
        }
    return {
        "ok": True,
        "detail": "database schema and integrity are valid",
        "counts": counts,
        "schema_version": schema_version,
    }


def _inspect_manifest(path: Path) -> dict[str, object]:
    if not path.is_file():
        return _manifest_inspection(
            schema_version=None,
            runtime_readable=False,
            detail=f"manifest not found: {path}",
        )
    schema_version: int | None = None
    manifest_text: str | None = None
    try:
        manifest_text = path.read_text(encoding="utf-8")
        raw_payload = json.loads(manifest_text)
        if isinstance(raw_payload, dict):
            raw_schema_version = raw_payload.get(
                "schema_version",
                LEGACY_MANIFEST_SCHEMA_VERSION,
            )
            if type(raw_schema_version) is int:
                schema_version = raw_schema_version
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        pass
    try:
        sources, chunks = load_sources_and_chunks(path.parent, path)
    except (OSError, ValueError) as exc:
        return _manifest_inspection(
            schema_version=schema_version,
            runtime_readable=False,
            detail=f"manifest invalid: {type(exc).__name__}",
        )
    try:
        if manifest_text is None or path.read_text(encoding="utf-8") != manifest_text:
            return _manifest_inspection(
                schema_version=None,
                runtime_readable=False,
                detail="manifest changed during inspection",
            )
    except (OSError, UnicodeError):
        return _manifest_inspection(
            schema_version=None,
            runtime_readable=False,
            detail="manifest changed during inspection",
        )
    migration_required = schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
    registration_compatible = _registration_manifest_compatible(
        path,
        manifest_text,
    )
    migration_detail = (
        "; schema migration required before protected source registration"
        if migration_required
        else ""
    )
    registration_detail = (
        "; registration writer requires a strict, safely replaceable manifest"
        if (
            schema_version == CURRENT_MANIFEST_SCHEMA_VERSION
            and not registration_compatible
        )
        else ""
    )
    return _manifest_inspection(
        schema_version=schema_version,
        runtime_readable=True,
        detail=(
            f"manifest valid; protected sources={len(sources)} "
            f"source chunks={len(chunks)}{migration_detail}{registration_detail}"
        ),
        registration_compatible=registration_compatible,
    )


def _manifest_inspection(
    *,
    schema_version: int | None,
    runtime_readable: bool,
    detail: str,
    registration_compatible: bool = False,
) -> dict[str, object]:
    migration_required = bool(
        runtime_readable
        and schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
    )
    return {
        "ok": runtime_readable,
        "detail": detail,
        "schema_version": schema_version,
        "runtime_readable": runtime_readable,
        "registration_writable": bool(
            runtime_readable
            and schema_version == CURRENT_MANIFEST_SCHEMA_VERSION
            and registration_compatible
        ),
        "migration_required": migration_required,
    }


def _registration_manifest_compatible(path: Path, text: str) -> bool:
    """Match the registration writer's non-mutating manifest preconditions."""

    try:
        metadata = os.lstat(path)
        workspace_metadata = os.stat(path.parent)
    except OSError:
        return False
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_dev != workspace_metadata.st_dev
        or metadata.st_size > MAX_PROTECTED_FILE_BYTES
    ):
        return False

    def reject_duplicate_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def reject_non_finite(_: str) -> None:
        raise ValueError("non-finite number")

    try:
        payload = json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_non_finite,
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    sources = payload.get("sources")
    if not isinstance(sources, list) or len(sources) > MAX_MANIFEST_SOURCES:
        return False

    canonical_paths: set[str] = set()
    root = os.path.abspath(path.parent)
    for source in sources:
        if not isinstance(source, dict):
            return False
        source_path = source.get("path")
        if not isinstance(source_path, str) or not source_path.strip():
            return False
        try:
            candidate = Path(source_path).expanduser()
            if not candidate.is_absolute():
                candidate = path.parent / candidate
            canonical = os.path.abspath(os.path.normpath(candidate))
            if os.path.commonpath((root, canonical)) != root:
                return False
        except (OSError, RuntimeError, TypeError, ValueError):
            return False
        if canonical in canonical_paths:
            return False
        canonical_paths.add(canonical)
    return True


def _inspect_data_directory_permissions(path: Path) -> tuple[bool, str]:
    if os.name != "posix":
        return True, "POSIX mode check is not applicable on this platform"
    if not path.is_dir():
        return False, f"data directory not found: {path}"
    mode = stat.S_IMODE(path.stat().st_mode)
    ok = mode & 0o077 == 0
    detail = f"{path} mode={mode:04o}"
    if not ok:
        detail += "; remove group/other permissions (for example, chmod 700)"
    return ok, detail


def _resolve_cli_workspace(path: Path) -> tuple[WorkspaceContext, Path]:
    absolute_path = _absolute_path(path)
    workspace = resolve_workspace(
        str(absolute_path),
        str(absolute_path),
        discovered_by="cli",
    )
    canonical_path = (
        absolute_path
        if workspace.canonical_root is None
        else Path(workspace.canonical_root)
    )
    return workspace, canonical_path


def _inspect_workspace_registration(
    db_path: Path,
    workspace: WorkspaceContext,
) -> tuple[bool, str]:
    if not workspace.ready or workspace.canonical_root is None:
        return False, f"workspace is not usable: {workspace.status}"
    if not db_path.is_file():
        return False, f"database not found: {db_path}"
    try:
        uri = f"{db_path.as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            row = conn.execute(
                "SELECT workspace_id FROM workspaces WHERE canonical_root = ?",
                (workspace.canonical_root,),
            ).fetchone()
    except sqlite3.Error as exc:
        return False, f"workspace registry unreadable: {type(exc).__name__}"
    if row is None:
        return False, "workspace is not registered; run 'tooluseproxy init --codex'"
    if row[0] != workspace.workspace_id:
        return False, "workspace registration identity does not match"
    return True, f"workspace registered: {workspace.workspace_id}"


def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _render(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print(f"status: {payload['status']}")
    for key, value in payload.items():
        if key in {
            "status",
            "checks",
            "database",
            "protected_sources",
            "workspace_registration",
        }:
            continue
        print(f"{key}: {value}")
    for item in payload.get("checks", []):
        marker = "ok" if item["ok"] else "error"
        print(f"[{marker}] {item['name']}: {item['detail']}")
    database = payload.get("database")
    if isinstance(database, dict):
        marker = "ok" if database.get("ok") else "error"
        print(f"[{marker}] database: {database.get('detail')}")
        for name, count in database.get("counts", {}).items():
            print(f"{name}: {count}")
    protected_sources = payload.get("protected_sources")
    if isinstance(protected_sources, dict):
        if not any(
            item.get("name") == "protected_sources"
            for item in payload.get("checks", [])
        ):
            marker = "ok" if protected_sources.get("ok") else "error"
            print(f"[{marker}] protected_sources: {protected_sources.get('detail')}")
        for key in (
            "schema_version",
            "runtime_readable",
            "registration_writable",
            "migration_required",
        ):
            print(f"protected_sources.{key}: {protected_sources.get(key)}")
    workspace_registration = payload.get("workspace_registration")
    if isinstance(workspace_registration, dict):
        marker = "ok" if workspace_registration.get("ok") else "error"
        print(
            f"[{marker}] workspace_registration: "
            f"{workspace_registration.get('detail')}"
        )


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _remove_sqlite_files(path: Path) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        candidate.unlink(missing_ok=True)


def _create_secure_empty_file(path: Path) -> None:
    """Reserve a new SQLite destination without a permissive creation window."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _backup_database_before_upgrade(db_path: Path) -> Path | None:
    if not db_path.is_file():
        return None
    uri = f"{db_path.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as source_conn:
        row = source_conn.execute("PRAGMA user_version").fetchone()
        version = 0 if row is None else int(row[0])
        if version == CURRENT_SCHEMA_VERSION:
            try:
                EventStore(db_path).require_runtime_schema()
            except SchemaCompatibilityError as exc:
                if exc.code != "schema_incomplete":
                    raise
            else:
                return None
        if version > CURRENT_SCHEMA_VERSION:
            raise ValueError(
                f"database schema v{version} is newer than runtime "
                f"v{CURRENT_SCHEMA_VERSION}"
            )
        backup_path = _available_backup_path(db_path, version)
        try:
            _create_secure_empty_file(backup_path)
            with sqlite3.connect(backup_path) as backup_conn:
                source_conn.backup(backup_conn)
                result = backup_conn.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise sqlite3.DatabaseError("migration backup failed quick_check")
        except Exception:
            _remove_sqlite_files(backup_path)
            raise
    secure_database_permissions(backup_path)
    return backup_path


def _available_backup_path(db_path: Path, version: int) -> Path:
    base = db_path.with_name(f"{db_path.name}.pre-migration-v{version}.bak")
    if not base.exists():
        return base
    index = 1
    while True:
        candidate = base.with_name(f"{base.name}.{index}")
        if not candidate.exists():
            return candidate
        index += 1
