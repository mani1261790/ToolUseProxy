from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


WORKSPACE_ID_VERSION = "ws_v1"
WORKSPACE_READY = "ready"
WORKSPACE_ROOT_ENV = "TOOLUSEPROXY_WORKSPACE_ROOT"


@dataclass(frozen=True)
class WorkspaceContext:
    workspace_id: str | None
    canonical_root: str | None
    lexical_root: str | None
    execution_cwd: str | None
    status: str
    discovered_by: str

    @property
    def ready(self) -> bool:
        return self.status == WORKSPACE_READY


def make_workspace_id(canonical_root: str) -> str:
    digest = hashlib.sha256(
        canonical_root.encode("utf-8", errors="surrogateescape")
    ).hexdigest()
    return f"{WORKSPACE_ID_VERSION}_{digest}"


def resolve_workspace(
    cwd: str | None,
    configured_root: str | None = None,
    *,
    discovered_by: str | None = None,
) -> WorkspaceContext:
    """Hook cwdと明示rootから、走査なしでworkspace identityを確定する。"""
    explicit_root = configured_root is not None
    source = discovered_by or ("configured_root" if explicit_root else "hook_cwd")
    if not explicit_root and cwd is None:
        return _unresolved("execution_cwd_missing", source)

    root_value = configured_root if explicit_root else cwd
    root = _validated_directory(root_value, prefix="workspace_root")
    if root.status is not None:
        return _unresolved(root.status, source)
    assert root.lexical_path is not None and root.canonical_path is not None
    workspace_id = make_workspace_id(root.canonical_path)

    if not explicit_root:
        return WorkspaceContext(
            workspace_id=workspace_id,
            canonical_root=root.canonical_path,
            lexical_root=root.lexical_path,
            execution_cwd=root.canonical_path,
            status=WORKSPACE_READY,
            discovered_by=source,
        )

    execution = _validated_directory(cwd, prefix="execution_cwd")
    if execution.status is not None:
        return _unresolved(execution.status, source)
    assert execution.canonical_path is not None
    try:
        inside_workspace = (
            os.path.commonpath((root.canonical_path, execution.canonical_path))
            == root.canonical_path
        )
    except ValueError:
        inside_workspace = False
    if not inside_workspace:
        return _unresolved("execution_cwd_outside_workspace", source)
    return WorkspaceContext(
        workspace_id=workspace_id,
        canonical_root=root.canonical_path,
        lexical_root=root.lexical_path,
        execution_cwd=execution.canonical_path,
        status=WORKSPACE_READY,
        discovered_by=source,
    )


@dataclass(frozen=True)
class _ValidatedDirectory:
    lexical_path: str | None
    canonical_path: str | None
    status: str | None


def _validated_directory(
    value: str | None,
    *,
    prefix: str,
) -> _ValidatedDirectory:
    if value is None:
        return _ValidatedDirectory(None, None, f"{prefix}_missing")
    if value == "":
        return _ValidatedDirectory(None, None, f"{prefix}_empty")
    try:
        candidate = Path(value).expanduser()
    except (OSError, RuntimeError, ValueError):
        return _ValidatedDirectory(None, None, f"{prefix}_io_error")
    if not candidate.is_absolute():
        return _ValidatedDirectory(None, None, f"{prefix}_not_absolute")
    try:
        lexical = os.path.abspath(os.path.normpath(str(candidate)))
    except (OSError, ValueError):
        return _ValidatedDirectory(None, None, f"{prefix}_io_error")
    try:
        metadata = os.lstat(lexical)
    except FileNotFoundError:
        return _ValidatedDirectory(lexical, None, f"{prefix}_path_missing")
    except PermissionError:
        return _ValidatedDirectory(lexical, None, f"{prefix}_permission_denied")
    except (OSError, ValueError):
        return _ValidatedDirectory(lexical, None, f"{prefix}_io_error")
    if stat.S_ISLNK(metadata.st_mode):
        return _ValidatedDirectory(lexical, None, f"{prefix}_symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        return _ValidatedDirectory(lexical, None, f"{prefix}_not_directory")
    try:
        canonical = _canonical_directory_path(lexical)
    except (OSError, ValueError):
        return _ValidatedDirectory(lexical, None, f"{prefix}_io_error")
    return _ValidatedDirectory(lexical, canonical, None)


def _canonical_directory_path(lexical: str) -> str:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(lexical, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise NotADirectoryError(lexical)
        if sys.platform == "darwin":
            import fcntl

            # Darwin F_GETPATH。PATH_MAXは1024で、open済みfdからfilesystemが
            # 保持するcanonical caseを取得する。
            raw_path = fcntl.fcntl(descriptor, 50, b"\0" * 1024)
            canonical = os.fsdecode(raw_path.split(b"\0", 1)[0])
            if not canonical or not os.path.isabs(canonical):
                raise OSError("F_GETPATH returned an invalid path")
            return os.path.normpath(canonical)
        return os.path.realpath(lexical)
    finally:
        os.close(descriptor)


def _unresolved(status: str, discovered_by: str) -> WorkspaceContext:
    return WorkspaceContext(
        workspace_id=None,
        canonical_root=None,
        lexical_root=None,
        execution_cwd=None,
        status=status,
        discovered_by=discovered_by,
    )
