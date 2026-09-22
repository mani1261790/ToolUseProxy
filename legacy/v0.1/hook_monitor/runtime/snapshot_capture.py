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


class _TimeBudgetExceeded(OSError):
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
    started_at = time.monotonic()
    limits = limits or SnapshotCaptureLimits()
    max_records = max(1, limits.max_paths * 2)
    if len(operations) > max_records:
        return []
    workspace_root = (
        event.workspace_root if event.workspace_status == "ready" else None
    )
    execution_cwd = (
        event.workspace_execution_cwd
        if event.workspace_status == "ready"
        else None
    )
    specs = _snapshot_specs(
        operations,
        workspace_root=workspace_root,
        execution_cwd=execution_cwd,
    )
    if not specs or len(specs) > max_records:
        return []
    budget = _Budget(
        remaining_bytes=limits.max_tool_bytes,
        deadline=started_at + limits.time_budget_ms / 1000,
    )
    seen_paths: set[str] = set()
    cache: dict[tuple[str, bool], _CaptureResult] = {}
    results: list[ResourceSnapshot] = []

    root_fd: int | None = None
    root_error: _CaptureResult | None = None
    if time.monotonic() >= budget.deadline:
        root_error = _CaptureResult(
            lexical_path=None,
            resource_state="unknown",
            capture_status="time_budget_exhausted",
            file_kind="unknown",
            error_code="time_budget",
        )
    elif workspace_root is None:
        root_error = _CaptureResult(
            lexical_path=None,
            resource_state="unknown",
            capture_status="invalid_workspace",
            file_kind="unknown",
            error_code="invalid_workspace",
        )
    else:
        try:
            _ensure_time_remaining(budget.deadline)
            root_stat = os.lstat(workspace_root)
            _ensure_time_remaining(budget.deadline)
            if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
                raise _SymlinkRejected()
            root_fd = os.open(
                workspace_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            _ensure_time_remaining(budget.deadline)
        except _TimeBudgetExceeded:
            root_error = _CaptureResult(
                lexical_path=None,
                resource_state="unknown",
                capture_status="time_budget_exhausted",
                file_kind="unknown",
                error_code="time_budget",
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
        # 実取得できる最終候補を先に処理する。大量のsuperseded statusが
        # record枠を使い切って最終内容のhashを落とすことを避ける。
        ordered_specs = sorted(
            specs,
            key=lambda spec: (
                not spec.capture_allowed,
                spec.operation.operation_index,
                spec.path_role,
            ),
        )
        for spec in ordered_specs:
            if len(results) >= max_records:
                break
            started = time.monotonic()
            path_identity = _path_identity(
                workspace_root,
                execution_cwd,
                spec.requested_path,
            )
            cache_key = (path_identity, spec.expected_missing)
            if not spec.capture_allowed:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status=spec.skip_status or "execution_unknown",
                    file_kind="unknown",
                )
            elif root_error is not None:
                lexical_path = None
                if workspace_root is not None:
                    lexical_path, _ = _lexical_path(
                        workspace_root,
                        execution_cwd,
                        spec.requested_path,
                    )
                captured = replace(root_error, lexical_path=lexical_path)
            elif time.monotonic() >= budget.deadline:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status="time_budget_exhausted",
                    file_kind="unknown",
                )
            elif cache_key in cache:
                captured = _cached_capture(cache[cache_key])
            elif path_identity not in seen_paths and len(seen_paths) >= limits.max_paths:
                captured = _CaptureResult(
                    lexical_path=None,
                    resource_state="unknown",
                    capture_status="path_limit",
                    file_kind="unknown",
                )
            else:
                seen_paths.add(path_identity)
                assert workspace_root is not None and root_fd is not None
                captured = _capture_path(
                    root_fd,
                    workspace_root,
                    execution_cwd,
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
            if (
                captured.capture_status in {"path_limit", "time_budget_exhausted"}
                or (spec.capture_allowed and root_error is not None)
            ):
                break
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return results


def _cached_capture(captured: _CaptureResult) -> _CaptureResult:
    """同一pathの再利用ではplaintextと取得byteを重複保存しない。"""
    status = captured.capture_status
    if captured.content_sha256 is not None:
        status = "cached_hash_only"
    return replace(
        captured,
        capture_status=status,
        captured_bytes=0,
        body_text=None,
    )


def _snapshot_specs(
    operations: list[ToolOperation],
    *,
    workspace_root: str | None,
    execution_cwd: str | None,
) -> list[_SnapshotSpec]:
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

    target_indexes_by_path: dict[str, list[int]] = {}
    for index, spec in enumerate(specs):
        if spec.path_role == "target":
            target_indexes_by_path.setdefault(
                _path_identity(
                    workspace_root,
                    execution_cwd,
                    spec.requested_path,
                ),
                [],
            ).append(index)

    normalized = list(specs)
    for indexes in target_indexes_by_path.values():
        last_index = indexes[-1]
        last_spec = specs[last_index]
        final_writer_is_ambiguous = (
            not last_spec.capture_allowed
            or any(specs[index].operation.connector == "pipe" for index in indexes)
        )
        if final_writer_is_ambiguous and len(indexes) > 1:
            for index in indexes:
                normalized[index] = replace(
                    specs[index],
                    capture_allowed=False,
                    skip_status="ambiguous_final_writer",
                )
            continue
        for index in indexes[:-1]:
            normalized[index] = replace(
                specs[index],
                capture_allowed=False,
                skip_status="superseded_by_later_operation",
            )
    return normalized


def _path_identity(
    workspace_root: str | None,
    execution_cwd: str | None,
    requested_path: str,
) -> str:
    if workspace_root is not None and execution_cwd is not None:
        lexical_path, _ = _lexical_path(
            workspace_root,
            execution_cwd,
            requested_path,
        )
        if lexical_path is not None:
            return lexical_path
    return os.path.normpath(str(Path(requested_path).expanduser()))


def _capture_path(
    root_fd: int,
    workspace_root: str,
    execution_cwd: str | None,
    spec: _SnapshotSpec,
    limits: SnapshotCaptureLimits,
    budget: _Budget,
    *,
    store_plaintext: bool,
) -> _CaptureResult:
    lexical_path, relative_parts = _lexical_path(
        workspace_root,
        execution_cwd,
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
        _ensure_time_remaining(budget.deadline)
        file_fd = _open_regular_file(
            root_fd,
            relative_parts,
            directory_fds,
            deadline=budget.deadline,
        )
        _ensure_time_remaining(budget.deadline)
        before = os.fstat(file_fd)
        _ensure_time_remaining(budget.deadline)
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
        while captured_bytes < before.st_size:
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
            read_size = min(
                64 * 1024,
                before.st_size - captured_bytes,
                budget.remaining_bytes,
            )
            if read_size <= 0:
                return _CaptureResult(
                    lexical_path=lexical_path,
                    resource_state="present",
                    capture_status="tool_total_limit",
                    file_kind="regular",
                    byte_size=before.st_size,
                    captured_bytes=captured_bytes,
                    error_code="tool_total_limit",
                )
            chunk = os.read(file_fd, read_size)
            if not chunk:
                break
            chunks.append(chunk)
            captured_bytes += len(chunk)
            budget.remaining_bytes -= len(chunk)
            _ensure_time_remaining(budget.deadline)

        _ensure_time_remaining(budget.deadline)
        after = os.fstat(file_fd)
        _ensure_time_remaining(budget.deadline)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
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
        _ensure_time_remaining(budget.deadline)
        digest = hashlib.sha256(data).hexdigest()
        _ensure_time_remaining(budget.deadline)
        try:
            text = data.decode("utf-8")
            is_binary = b"\0" in data
        except UnicodeDecodeError:
            text = ""
            is_binary = True
        _ensure_time_remaining(budget.deadline)
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
    except _TimeBudgetExceeded:
        return _CaptureResult(
            lexical_path=lexical_path,
            resource_state="unknown",
            capture_status="time_budget_exhausted",
            file_kind="unknown",
            error_code="time_budget",
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
    *,
    deadline: float,
) -> int:
    if not parts:
        raise IsADirectoryError()
    current_fd = root_fd
    for component in parts[:-1]:
        _ensure_time_remaining(deadline)
        component_stat = os.stat(
            component,
            dir_fd=current_fd,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(component_stat.st_mode):
            raise _SymlinkRejected()
        _ensure_time_remaining(deadline)
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

    _ensure_time_remaining(deadline)
    final_stat = os.stat(
        parts[-1],
        dir_fd=current_fd,
        follow_symlinks=False,
    )
    if stat.S_ISLNK(final_stat.st_mode):
        raise _SymlinkRejected()
    if not stat.S_ISREG(final_stat.st_mode):
        raise _NonRegularRejected()
    _ensure_time_remaining(deadline)
    return os.open(
        parts[-1],
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=current_fd,
    )


def _ensure_time_remaining(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise _TimeBudgetExceeded()


def _lexical_path(
    workspace_root: str,
    execution_cwd: str | None,
    requested_path: str,
) -> tuple[str | None, tuple[str, ...] | None]:
    candidate = Path(requested_path).expanduser()
    if not candidate.is_absolute():
        if execution_cwd is None:
            return None, None
        candidate = Path(execution_cwd) / candidate
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
