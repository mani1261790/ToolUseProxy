from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from hook_monitor.runtime.source_config import SourceConfigError, load_protected_sources
from hook_monitor.runtime.storage import (
    CURRENT_SCHEMA_VERSION,
    EventStore,
    SchemaCompatibilityError,
)
from hook_monitor.runtime.workspace import WorkspaceContext, resolve_workspace
from tooluseproxy import __version__
from tooluseproxy.integrations.codex import CODEX_HOOK_PHASES, run_codex_hook
from tooluseproxy.paths import (
    PathConfigurationError,
    prepare_data_directory,
    resolve_runtime_paths,
    secure_database_permissions,
)


MANIFEST_FILENAME = "protected_sources.json"


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
    manifest_ok, manifest_detail = _inspect_manifest(manifest_path)
    checks.append(_check("protected_sources", manifest_ok, manifest_detail))

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
    manifest_ok, manifest_detail = _inspect_manifest(workspace_path / MANIFEST_FILENAME)
    payload = {
        "status": (
            "active"
            if workspace.ready and summary["ok"] and registration_ok and manifest_ok
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
        "protected_sources": {
            "ok": manifest_ok,
            "detail": manifest_detail,
        },
    }
    _render(payload, as_json=args.json)
    return 0 if payload["status"] == "active" else 1


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
        load_protected_sources(path)
        return False
    payload = {"schema_version": 1, "sources": []}
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
            load_protected_sources(path)
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


def _inspect_manifest(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, f"manifest not found: {path}"
    try:
        sources = load_protected_sources(path)
    except (OSError, json.JSONDecodeError, SourceConfigError) as exc:
        return False, f"manifest invalid: {type(exc).__name__}"
    return True, f"manifest valid; protected sources={len(sources)}"


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
        marker = "ok" if protected_sources.get("ok") else "error"
        print(f"[{marker}] protected_sources: {protected_sources.get('detail')}")
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
