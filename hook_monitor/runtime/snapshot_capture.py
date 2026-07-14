from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path

from hook_monitor.runtime.models import NormalizedEvent, ResourceSnapshot, ToolOperation


@dataclass(frozen=True)
class SnapshotCaptureLimits:
    max_file_bytes: int = 256 * 1024
    max_tool_bytes: int = 1024 * 1024
    max_paths: int = 32
    time_budget_ms: int = 250


@dataclass(frozen=True)
class _SnapshotSpec:
    operation: ToolOperation
    path_role: str
    requested_path: str
    expected_missing: bool
    capture_allowed: bool = True
    skip_status: str | None = None


@dataclass(frozen=True)
class _CaptureResult:
    lexical_path: str | None
    resource_state: str
    capture_status: str
    file_kind: str
    byte_size: int | None = None
    captured_bytes: int = 0
    content_sha256: str | None = None
    encoding: str | None = None
    body_text: str | None = None
    error_code: str | None = None
    duration_ms: float = 0.0


@dataclass
class _Budget:
    remaining_bytes: int
    deadline: float


class _SymlinkRejected(OSError):
    pass


class _NonRegularRejected(OSError):
    pass


def limits_from_environment() -> SnapshotCaptureLimits:
    return SnapshotCaptureLimits(
        max_file_bytes=_bounded_env_int(
            "TOOLUSEPROXY_SNAPSHOT_MAX_FILE_BYTES",
            256 * 1024,
            4 * 1024 * 1024,
        ),
        max_tool_bytes=_bounded_env_int(
            "TOOLUSEPROXY_SNAPSHOT_MAX_TOOL_BYTES",
            1024 * 1024,
            16 * 1024 * 1024,
        ),
        max_paths=_bounded_env_int(
            "TOOLUSEPROXY_SNAPSHOT_MAX_PATHS",
            32,
            128,
        ),
        time_budget_ms=_bounded_env_int(
            "TOOLUSEPROXY_SNAPSHOT_TIME_BUDGET_MS",
            250,
            1000,
        ),
    )


def plaintext_snapshots_enabled() -> bool:
    value = os.environ.get("TOOLUSEPROXY_SNAPSHOT_PLAINTEXT", "0")
    return value.casefold() in {"1", "true", "yes", "on"}


def capture_operation_snapshots(
    event: NormalizedEvent,
    operations: list[ToolOperation],
    *,
    limits: SnapshotCaptureLimits | None = None,
    store_plaintext: bool = False,
) -> list[ResourceSnapshot]:
    """成功PostToolUseに対応する静的pathだけをbounded captureする。"""
    limits = limits or SnapshotCaptureLimits()
    specs = _snapshot_specs(operations)
    if not specs:
        return []
    workspace_root = _workspace_root(event.cwd)
    budget = _Budget(
        remaining_bytes=limits.max_tool_bytes,
        deadline=time.monotonic() + limits.time_budget_ms / 1000,
    )
    seen_paths: set[str] = set()
    cache: dict[tuple[str, bool], _CaptureResult] = {}
    results: list[ResourceSnapshot] = []

    root_fd: int | None = None
    root_error: _CaptureResult | None = None
    if workspace_root is None:
        root_error = _CaptureResult(
            lexical_path=None,
            resource_state="unknown",
            capture_status="invalid_workspace",
            file_kind="unknown",
            error_code="invalid_workspace",
        )
    else:
        try:
            root_stat = os.lstat(workspace_root)
            if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
                raise _SymlinkRejected()
            root_fd = os.open(
                workspace_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except _SymlinkRejected:
            root_error = _CaptureResult(
                lexical_path=workspace_root,
                resource_state="unknown",
                capture_status="symlink_rejected",
                file_kind="symlink",
                error_code="workspace_symlink",
            )
        except OSError as exc:
            root_error = _CaptureResult(
                lexical_path=workspace_root,
                resource_state="unknown",
                capture_status="invalid_workspace",
                file_kind="unknown",
                error_code=_stable_error_code(exc),
            )

    try:
        for spec in specs:
            started = time.monotonic()
            cache_key = (spec.requested_path, spec.expected_missing)
            if not spec.capture_allowed:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status=spec.skip_status or "execution_unknown",
                    file_kind="unknown",
                )
            elif root_error is not None:
                captured = root_error
            elif time.monotonic() >= budget.deadline:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status="time_budget_exhausted",
                    file_kind="unknown",
                )
            elif cache_key in cache:
                captured = cache[cache_key]
            elif spec.requested_path not in seen_paths and len(seen_paths) >= limits.max_paths:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status="path_limit",
                    file_kind="unknown",
                )
            else:
                seen_paths.add(spec.requested_path)
                assert workspace_root is not None and root_fd is not None
                captured = _capture_path(
                    root_fd,
                    workspace_root,
                    spec,
                    limits,
                    budget,
                    store_plaintext=store_plaintext,
                )
                cache[cache_key] = captured
            elapsed_ms = (time.monotonic() - started) * 1000
            captured = replace(captured, duration_ms=elapsed_ms)
            results.append(
                _resource_snapshot(
                    event,
                    spec,
                    workspace_root,
                    captured,
                )
            )
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return results


def _snapshot_specs(operations: list[ToolOperation]) -> list[_SnapshotSpec]:
    specs: list[_SnapshotSpec] = []
    for operation in sorted(
        operations,
        key=lambda item: (item.operation_index, item.operation_id),
    ):
        conditional = operation.adapter == "bash" and operation.connector in {
            "and_then",
            "or_else",
        }
        if operation.operation_kind in {"add", "update", "overwrite", "append"}:
            if operation.target_path is not None:
                specs.append(
                    _SnapshotSpec(
                        operation=operation,
                        path_role="target",
                        requested_path=operation.target_path,
                        expected_missing=False,
                        capture_allowed=not conditional,
                        skip_status="execution_unknown" if conditional else None,
                    )
                )
        elif operation.operation_kind == "move":
            if operation.source_path is not None:
                specs.append(
                    _SnapshotSpec(
                        operation=operation,
                        path_role="source",
                        requested_path=operation.source_path,
                        expected_missing=True,
                    )
                )
            if operation.target_path is not None:
                specs.append(
                    _SnapshotSpec(
                        operation=operation,
                        path_role="target",
                        requested_path=operation.target_path,
                        expected_missing=False,
                    )
                )
        elif operation.operation_kind == "delete" and operation.source_path is not None:
            specs.append(
                _SnapshotSpec(
                    operation=operation,
                    path_role="source",
                    requested_path=operation.source_path,
                    expected_missing=True,
                )
            )

    last_target_by_path: dict[str, int] = {}
    for index, spec in enumerate(specs):
        if spec.path_role == "target":
            last_target_by_path[spec.requested_path] = index
    return [
        replace(
            spec,
            capture_allowed=False,
            skip_status="superseded_by_later_operation",
        )
        if spec.path_role == "target"
        and last_target_by_path.get(spec.requested_path) != index
        else spec
        for index, spec in enumerate(specs)
    ]


def _capture_path(
    root_fd: int,
    workspace_root: str,
    spec: _SnapshotSpec,
    limits: SnapshotCaptureLimits,
    budget: _Budget,
    *,
    store_plaintext: bool,
) -> _CaptureResult:
    lexical_path, relative_parts = _lexical_path(
        workspace_root,
        spec.requested_path,
    )
    if lexical_path is None or relative_parts is None:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="unknown",
            capture_status="outside_workspace",
            file_kind="unknown",
            error_code="outside_workspace",
        )

    file_fd: int | None = None
    directory_fds: list[int] = []
    try:
        file_fd = _open_regular_file(root_fd, relative_parts, directory_fds)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            return _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status="non_regular",
                file_kind="non_regular",
                byte_size=before.st_size,
                error_code="non_regular",
            )
        if before.st_size > limits.max_file_bytes:
            return _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status="file_too_large",
                file_kind="regular",
                byte_size=before.st_size,
                error_code="file_limit",
            )
        if before.st_size > budget.remaining_bytes:
            return _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status="tool_total_limit",
                file_kind="regular",
                byte_size=before.st_size,
                error_code="tool_total_limit",
            )

        chunks: list[bytes] = []
        captured_bytes = 0
        while True:
            if time.monotonic() >= budget.deadline:
                return _CaptureResult(
                    lexical_path=lexical_path,
                    resource_state="present",
                    capture_status="time_budget_exhausted",
                    file_kind="regular",
                    byte_size=before.st_size,
                    captured_bytes=captured_bytes,
                    error_code="time_budget",
                )
            chunk = os.read(file_fd, min(64 * 1024, limits.max_file_bytes + 1))
            if not chunk:
                break
            chunks.append(chunk)
            captured_bytes += len(chunk)
            budget.remaining_bytes -= len(chunk)
            if captured_bytes > limits.max_file_bytes or budget.remaining_bytes < 0:
                return _CaptureResult(
                    lexical_path=lexical_path,
                    resource_state="present",
                    capture_status="tool_total_limit",
                    file_kind="regular",
                    byte_size=before.st_size,
                    captured_bytes=captured_bytes,
                    error_code="bounded_read_exceeded",
                )

        after = os.fstat(file_fd)
        if (
            before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or captured_bytes != after.st_size
        ):
            return _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status="unstable_file",
                file_kind="regular",
                byte_size=after.st_size,
                captured_bytes=captured_bytes,
                error_code="file_changed_during_capture",
            )

        data = b"".join(chunks)
        digest = hashlib.sha256(data).hexdigest()
        try:
            text = data.decode("utf-8")
            is_binary = b"\0" in data
        except UnicodeDecodeError:
            text = ""
            is_binary = True
        if is_binary:
            result = _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status="binary_hash_only",
                file_kind="regular_binary",
                byte_size=after.st_size,
                captured_bytes=captured_bytes,
                content_sha256=digest,
            )
        else:
            result = _CaptureResult(
                lexical_path=lexical_path,
                resource_state="present",
                capture_status=(
                    "captured_text" if store_plaintext else "captured_hash_only"
                ),
                file_kind="regular_text",
                byte_size=after.st_size,
                captured_bytes=captured_bytes,
                content_sha256=digest,
                encoding="utf-8",
                body_text=text if store_plaintext else None,
            )
        if spec.expected_missing:
            return replace(
                result,
                capture_status="delete_not_effective",
                error_code="expected_missing_but_present",
            )
        return result
    except FileNotFoundError:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="deleted" if spec.expected_missing else "missing",
            capture_status="deleted" if spec.expected_missing else "missing_unexpected",
            file_kind="missing",
            error_code=None if spec.expected_missing else "missing",
        )
    except _SymlinkRejected:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="unknown",
            capture_status="symlink_rejected",
            file_kind="symlink",
            error_code="symlink_component",
        )
    except _NonRegularRejected:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="present",
            capture_status="non_regular",
            file_kind="non_regular",
            error_code="non_regular",
        )
    except OSError as exc:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="unknown",
            capture_status="read_error",
            file_kind="unknown",
            error_code=_stable_error_code(exc),
        )
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


def _open_regular_file(
    root_fd: int,
    parts: tuple[str, ...],
    directory_fds: list[int],
) -> int:
    if not parts:
        raise IsADirectoryError()
    current_fd = root_fd
    for component in parts[:-1]:
        component_stat = os.stat(
            component,
            dir_fd=current_fd,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(component_stat.st_mode):
            raise _SymlinkRejected()
        descriptor = os.open(
            component,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=current_fd,
        )
        directory_fds.append(descriptor)
        current_fd = descriptor

    final_stat = os.stat(
        parts[-1],
        dir_fd=current_fd,
        follow_symlinks=False,
    )
    if stat.S_ISLNK(final_stat.st_mode):
        raise _SymlinkRejected()
    if not stat.S_ISREG(final_stat.st_mode):
        raise _NonRegularRejected()
    return os.open(
        parts[-1],
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=current_fd,
    )


def _lexical_path(
    workspace_root: str,
    requested_path: str,
) -> tuple[str | None, tuple[str, ...] | None]:
    candidate = Path(requested_path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(workspace_root) / candidate
    lexical = os.path.abspath(os.path.normpath(str(candidate)))
    try:
        if os.path.commonpath((workspace_root, lexical)) != workspace_root:
            return lexical, None
    except ValueError:
        return lexical, None
    relative = os.path.relpath(lexical, workspace_root)
    parts = tuple(part for part in Path(relative).parts if part not in {"", "."})
    if any(part == ".." for part in parts):
        return lexical, None
    return lexical, parts


def _workspace_root(cwd: str | None) -> str | None:
    if cwd is None:
        return None
    candidate = Path(cwd).expanduser()
    if not candidate.is_absolute():
        return None
    return os.path.abspath(os.path.normpath(str(candidate)))


def _resource_snapshot(
    event: NormalizedEvent,
    spec: _SnapshotSpec,
    workspace_root: str | None,
    captured: _CaptureResult,
) -> ResourceSnapshot:
    identity = "\0".join(
        (event.event_id, spec.operation.operation_id, spec.path_role)
    )
    return ResourceSnapshot(
        snapshot_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        post_event_id=event.event_id,
        operation_id=spec.operation.operation_id,
        session_id=event.session_id,
        tool_use_id=event.tool_use_id,
        path_role=spec.path_role,
        requested_path=spec.requested_path,
        workspace_root=workspace_root,
        lexical_path=captured.lexical_path,
        resource_state=captured.resource_state,
        capture_status=captured.capture_status,
        file_kind=captured.file_kind,
        byte_size=captured.byte_size,
        captured_bytes=captured.captured_bytes,
        content_sha256=captured.content_sha256,
        encoding=captured.encoding,
        body_text=captured.body_text,
        error_code=captured.error_code,
        duration_ms=captured.duration_ms,
    )


def _stable_error_code(exc: OSError) -> str:
    return {
        errno.EACCES: "permission_denied",
        errno.EPERM: "permission_denied",
        errno.ENOENT: "missing",
        errno.ENOTDIR: "not_directory",
        errno.ELOOP: "symlink_component",
    }.get(exc.errno, "io_error")


def _bounded_env_int(name: str, default: int, hard_maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    if value <= 0:
        return default
    return min(value, hard_maximum)
