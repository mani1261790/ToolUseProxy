from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


UNINSTALL_SCHEMA_VERSION = 1
MANIFEST_BACKUP_DIRECTORY = "manifest-backups"
DATABASE_FILENAME = "events.db"
DATA_DIRECTORY_MARKER = ".tooluseproxy-data.json"
_MARKER_PAYLOAD = {
    "product": "ToolUseProxy",
    "purpose": "local-runtime-data",
    "schema_version": 1,
}
_MARKER_BYTES = (
    json.dumps(_MARKER_PAYLOAD, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
).encode("utf-8")
_DATABASE_SIDECAR_NAMES = (
    DATABASE_FILENAME,
    f"{DATABASE_FILENAME}.workspaces",
    f"{DATABASE_FILENAME}-journal",
    f"{DATABASE_FILENAME}-shm",
    f"{DATABASE_FILENAME}-wal",
)
_MIGRATION_BACKUP_PATTERN = re.compile(
    r"^events\.db\.pre-migration-v[0-9]+\.bak(?:\.[0-9]+)?"
    r"(?:-(?:journal|shm|wal))?$"
)


class UninstallError(ValueError):
    pass


@dataclass(frozen=True)
class ManagedDataPlan:
    data_dir: Path
    managed_roots: tuple[Path, ...]
    managed_entry_count: int
    managed_file_count: int
    managed_bytes: int
    unmanaged_entry_count: int
    confirmation_token: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": UNINSTALL_SCHEMA_VERSION,
            "status": (
                "review_required"
                if self.confirmation_token is not None
                else "nothing_to_delete"
            ),
            "action": "delete_managed_data",
            "data_dir": str(self.data_dir),
            "managed_entry_count": self.managed_entry_count,
            "managed_file_count": self.managed_file_count,
            "managed_bytes": self.managed_bytes,
            "unmanaged_entry_count": self.unmanaged_entry_count,
            "confirmation_token": self.confirmation_token,
            "plugin_code_removal": "separate_codex_command_required",
            "package_removal": "separate_package_manager_command_required",
            "review_required": self.confirmation_token is not None,
        }


def ensure_data_directory_marker(data_dir: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(data_dir.expanduser())))
    marker = requested / DATA_DIRECTORY_MARKER
    if marker.exists() or marker.is_symlink():
        _validate_marker(marker)
        return marker
    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(_MARKER_BYTES)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        marker.unlink(missing_ok=True)
        raise
    return marker


def plan_managed_data_deletion(data_dir: Path) -> ManagedDataPlan:
    requested = Path(os.path.abspath(os.fspath(data_dir.expanduser())))
    if requested.is_symlink():
        raise UninstallError("data directory must not be a symlink")
    if not requested.exists():
        return ManagedDataPlan(requested, (), 0, 0, 0, 0, None)
    if not requested.is_dir():
        raise UninstallError("data directory is not a directory")
    if os.name == "posix" and stat.S_IMODE(requested.stat().st_mode) & 0o077:
        raise UninstallError("data directory must not be accessible by group or other users")

    canonical = requested.resolve(strict=True)
    candidate_roots: list[Path] = []
    unmanaged_entry_count = 0
    for entry in sorted(canonical.iterdir(), key=lambda path: os.fsencode(path.name)):
        if _is_managed_root(entry.name):
            candidate_roots.append(entry)
        else:
            unmanaged_entry_count += 1

    if candidate_roots and not _has_tooluseproxy_identity(canonical):
        raise UninstallError(
            "managed-looking files are not identifiable as ToolUseProxy data"
        )
    managed_roots = sorted(
        candidate_roots,
        key=lambda path: (path.name == DATA_DIRECTORY_MARKER, os.fsencode(path.name)),
    )

    inventory: list[dict[str, object]] = []
    for root in managed_roots:
        _inventory_path(root, canonical, inventory)
    inventory.sort(key=lambda item: os.fsencode(str(item["path"])))
    managed_file_count = sum(item["kind"] == "file" for item in inventory)
    managed_bytes = sum(
        int(item["size"])
        for item in inventory
        if item["kind"] == "file"
    )
    token = None
    if inventory:
        token_payload = {
            "schema_version": UNINSTALL_SCHEMA_VERSION,
            "action": "delete_managed_data",
            "data_dir": str(canonical),
            "inventory": inventory,
        }
        encoded = json.dumps(
            token_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        token = hashlib.sha256(encoded).hexdigest()
    return ManagedDataPlan(
        canonical,
        tuple(managed_roots),
        len(inventory),
        managed_file_count,
        managed_bytes,
        unmanaged_entry_count,
        token,
    )


def apply_managed_data_deletion(
    data_dir: Path,
    *,
    confirmation_token: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", confirmation_token):
        raise UninstallError("confirmation token is invalid")
    plan = plan_managed_data_deletion(data_dir)
    if plan.confirmation_token is None:
        raise UninstallError("no managed ToolUseProxy data exists at the selected directory")
    if not hmac.compare_digest(plan.confirmation_token, confirmation_token):
        raise UninstallError("managed data changed after review; create a new uninstall plan")

    for root in plan.managed_roots:
        metadata = os.lstat(root)
        if stat.S_ISREG(metadata.st_mode):
            root.unlink()
        elif stat.S_ISDIR(metadata.st_mode):
            shutil.rmtree(root)
        else:
            raise UninstallError("managed data type changed after review")

    data_directory_removed = False
    try:
        plan.data_dir.rmdir()
    except OSError:
        pass
    else:
        data_directory_removed = True
    remaining = plan_managed_data_deletion(plan.data_dir)
    if remaining.confirmation_token is not None:
        raise UninstallError("managed data was recreated during uninstall")
    return {
        "schema_version": UNINSTALL_SCHEMA_VERSION,
        "status": "deleted",
        "action": "delete_managed_data",
        "data_dir": str(plan.data_dir),
        "deleted_entry_count": plan.managed_entry_count,
        "deleted_file_count": plan.managed_file_count,
        "deleted_bytes": plan.managed_bytes,
        "data_directory_removed": data_directory_removed,
        "unmanaged_entry_count": remaining.unmanaged_entry_count,
        "unmanaged_entries_retained": remaining.unmanaged_entry_count > 0,
        "plugin_code_removal": "separate_codex_command_required",
        "package_removal": "separate_package_manager_command_required",
    }


def _is_managed_root(name: str) -> bool:
    return (
        name == DATA_DIRECTORY_MARKER
        or name in _DATABASE_SIDECAR_NAMES
        or name == MANIFEST_BACKUP_DIRECTORY
        or _MIGRATION_BACKUP_PATTERN.fullmatch(name) is not None
    )


def _has_tooluseproxy_identity(data_dir: Path) -> bool:
    marker = data_dir / DATA_DIRECTORY_MARKER
    if marker.exists() or marker.is_symlink():
        _validate_marker(marker)
        return True
    database_candidates = [data_dir / DATABASE_FILENAME]
    database_candidates.extend(
        path
        for path in data_dir.iterdir()
        if _MIGRATION_BACKUP_PATTERN.fullmatch(path.name) is not None
        and "-wal" not in path.name
        and "-shm" not in path.name
        and "-journal" not in path.name
    )
    return any(_is_tooluseproxy_database(path) for path in database_candidates)


def _validate_marker(marker: Path) -> None:
    metadata = os.lstat(marker)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077)
    ):
        raise UninstallError("ToolUseProxy data marker is not a private regular file")
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UninstallError("ToolUseProxy data marker is invalid") from error
    if payload != _MARKER_PAYLOAD:
        raise UninstallError("ToolUseProxy data marker is invalid")


def _is_tooluseproxy_database(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            return False
        uri = f"{path.resolve(strict=True).as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            version_row = connection.execute("PRAGMA user_version").fetchone()
            table_rows = connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return False
    version = 0 if version_row is None else int(version_row[0])
    tables = {str(row[0]) for row in table_rows}
    return version > 0 and {"events", "workspaces"}.issubset(tables)


def _inventory_path(
    path: Path,
    data_dir: Path,
    inventory: list[dict[str, object]],
) -> None:
    metadata = os.lstat(path)
    relative = path.relative_to(data_dir).as_posix()
    if stat.S_ISLNK(metadata.st_mode):
        raise UninstallError(f"managed data contains a symlink: {relative}")
    if stat.S_ISREG(metadata.st_mode):
        inventory.append(
            {
                "path": relative,
                "kind": "file",
                "size": metadata.st_size,
                "sha256": _sha256(path),
            }
        )
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise UninstallError(f"managed data contains an unsupported file type: {relative}")
    inventory.append({"path": relative, "kind": "directory"})
    for child in sorted(path.iterdir(), key=lambda candidate: os.fsencode(candidate.name)):
        _inventory_path(child, data_dir, inventory)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()
