"""Project selection before the Codex Plugin starts its shared runtime."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path

from hook_monitor.runtime.workspace import make_workspace_id, resolve_workspace

ACTIVATION_DIRECTORY_SUFFIX = ".workspaces"
ACTIVATION_MARKER_VERSION = 1
ACTIVATION_MARKER_MAX_BYTES = 4096


def activation_directory(database: Path) -> Path:
    return database.with_name(database.name + ACTIVATION_DIRECTORY_SUFFIX)


def activation_path(database: Path, root: str) -> Path:
    return activation_directory(database) / f"{make_workspace_id(root)}.json"


def _registered_roots(database: Path) -> list[str]:
    """Recover explicit evidence from an installation predating marker files."""
    with closing(sqlite3.connect(
        database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.05
    )) as connection:
        rows = connection.execute(
            "SELECT workspace_id, canonical_root, discovered_by FROM workspaces"
        ).fetchall()
        has_settings = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='workspace_runtime_settings'"
        ).fetchone()
        configured = set() if not has_settings else {
            row[0] for row in connection.execute(
                "SELECT workspace_id FROM workspace_runtime_settings"
            )
        }
        # workspaces also contains automatic observations, which are not consent.
        return [root for identity, root, source in rows if (
            source in {"init", "setup_profile"} or identity in configured
            or (Path(root) / "protected_sources.json").is_file()
        )]


def _read_marker(path: Path, expected_root: str) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("workspace activation marker is not a regular file")
    if metadata.st_size > ACTIVATION_MARKER_MAX_BYTES:
        raise ValueError("workspace activation marker is too large")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload != {"version": ACTIVATION_MARKER_VERSION, "root": expected_root}:
        raise ValueError("invalid workspace activation marker")
    return expected_root


def _marked_workspace_root(database: Path, execution_root: str) -> str | None:
    directory = activation_directory(database)
    if not directory.exists():
        return None
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("workspace activation directory is invalid")
    candidate = Path(execution_root)
    while True:
        root = str(candidate)
        marker = activation_path(database, root)
        if marker.exists() or marker.is_symlink():
            return _read_marker(marker, root)
        # Do not let an enabled parent silently activate an independent nested repo.
        if (candidate / ".git").exists() or (candidate / ".git").is_symlink():
            return None
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def enabled_workspace_root(database: Path, cwd: str | None) -> str | None:
    # A malformed payload affects only the project where the Hook is running.
    execution = resolve_workspace(cwd)
    if not execution.ready:
        execution = resolve_workspace(os.getcwd())
    if not execution.ready or execution.canonical_root is None:
        raise ValueError("Hook workspace cannot be identified safely")
    directory = activation_directory(database)
    if directory.exists() or directory.is_symlink():
        marked = _marked_workspace_root(database, execution.canonical_root)
        if marked is not None:
            return marked
        # Directory creation and first marker publication are separate system
        # calls. Until one complete marker exists, retain the legacy DB check.
        if any(directory.glob("ws_v1_*.json")):
            return None
    if not database.exists():
        return None
    # Compatibility path. Explicit setup migrates recoverable roots to markers.
    roots = _registered_roots(database)
    for root in sorted(roots, key=len, reverse=True):
        try:
            if os.path.commonpath((root, execution.canonical_root)) != root:
                continue
            relative = Path(execution.canonical_root).relative_to(root)
        except (TypeError, ValueError):
            continue
        cursor = Path(root)
        for part in relative.parts:
            cursor /= part
            if cursor != Path(root) and (
                (cursor / ".git").exists() or (cursor / ".git").is_symlink()
            ):
                break
        else:
            return root
    return None


def require_workspace_registration(database: Path, root: str) -> None:
    with closing(sqlite3.connect(
        database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.05
    )) as connection:
        if connection.execute(
            "SELECT 1 FROM workspaces WHERE canonical_root=?", (root,)
        ).fetchone() is None:
            raise ValueError("enabled workspace registration is missing")


def _save_marker(database: Path, root: str) -> None:
    directory = activation_directory(database)
    if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
        raise ValueError("workspace activation directory is invalid")
    directory.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        directory.chmod(0o700)
    target = activation_path(database, root)
    descriptor, temporary = tempfile.mkstemp(prefix=".workspace-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"version": ACTIVATION_MARKER_VERSION, "root": root}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        if os.name == "posix":
            directory_descriptor = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_workspace_activations(database: Path, root: str | None = None) -> None:
    """Persist explicit enrollments independently, without a shared-file race."""
    roots = set(_registered_roots(database))
    if root is not None:
        roots.add(root)
    for registered_root in sorted(roots):
        _save_marker(database, registered_root)
