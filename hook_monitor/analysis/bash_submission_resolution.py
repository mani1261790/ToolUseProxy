from __future__ import annotations

import errno
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from hook_monitor.analysis.bash_file_parser import (
    BashSegment,
    ShellToken,
    bash_segment_command_tokens,
    bash_segment_redirection_tokens,
    parse_bash_command_plan,
)
from hook_monitor.analysis.bash_submission import (
    MAX_BASH_SUBMISSION_TOTAL_BYTES,
    MAX_BASH_SUBMISSION_VALUE_BYTES,
    MAX_BASH_SUBMISSION_VALUES,
    extract_bash_http_submissions,
)


BASH_SUBMISSION_RESOLVER_VERSION = (
    "bash-submission-resolver-v3-fail-closed-data-binary-file"
)
MAX_BASH_SUBMISSION_PATH_BYTES = 4 * 1024
MAX_BASH_SUBMISSION_FILE_REFERENCES = 8
DEFAULT_BASH_SUBMISSION_RESOLUTION_TIME_BUDGET_MS = 200
MAX_BASH_SUBMISSION_RESOLUTION_TIME_BUDGET_MS = 1000

_KNOWN_ONE_ARGUMENT_OPTIONS = frozenset(
    {
        "-A",
        "--connect-timeout",
        "--header",
        "--max-time",
        "--output",
        "--proxy",
        "--request",
        "--retry",
        "--url",
        "--user-agent",
        "-H",
        "-m",
        "-o",
        "-x",
        "-X",
    }
)
_KNOWN_NO_ARGUMENT_OPTIONS = frozenset(
    {
        "-f",
        "-g",
        "-k",
        "-L",
        "-s",
        "-S",
        "-v",
        "--compressed",
        "--fail",
        "--fail-with-body",
        "--globoff",
        "--http1.1",
        "--http2",
        "--http3",
        "--insecure",
        "--location",
        "--next",
        "--show-error",
        "--silent",
        "--verbose",
    }
)
_OS_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd


@dataclass(frozen=True)
class BashResolvedSubmission:
    segment_index: int
    status: Literal["evaluated", "unsupported"]
    extraction: Literal["static_values", "resolved_file", "coarse_fallback"]
    submitted_values: tuple[str, ...] = field(repr=False)
    unsupported_reason: str | None = None


@dataclass
class _ResolutionBudget:
    deadline: float
    remaining_values: int = MAX_BASH_SUBMISSION_VALUES
    remaining_bytes: int = MAX_BASH_SUBMISSION_TOTAL_BYTES
    remaining_file_references: int = MAX_BASH_SUBMISSION_FILE_REFERENCES


def resolve_bash_http_submissions(
    command: str,
    *,
    workspace_root: Path,
    execution_cwd: Path,
    time_budget_ms: int = DEFAULT_BASH_SUBMISSION_RESOLUTION_TIME_BUDGET_MS,
) -> tuple[BashResolvedSubmission, ...]:
    """Resolve a narrow, bounded subset of file-backed curl bodies.

    The resolver never executes shell syntax or target tools. Version 2 accepts
    only static ``--data-binary @relative-file`` operands inside the workspace.
    File contents are returned only to the in-process caller and must not be
    persisted or rendered.
    """
    if (
        type(time_budget_ms) is not int
        or not 1 <= time_budget_ms <= MAX_BASH_SUBMISSION_RESOLUTION_TIME_BUDGET_MS
    ):
        raise ValueError("time_budget_ms must be between 1 and 1000")
    budget = _ResolutionBudget(
        deadline=time.monotonic() + time_budget_ms / 1000,
    )
    plan = parse_bash_command_plan(command)
    if plan is None:
        return ()
    static_by_segment = {
        projection.segment_index: projection
        for projection in extract_bash_http_submissions(command)
    }
    try:
        workspace = Path(workspace_root).resolve(strict=True)
        cwd = Path(execution_cwd).resolve(strict=True)
    except (OSError, RuntimeError):
        return tuple(
            _unsupported(segment, "workspace_or_cwd_unavailable")
            for segment in plan.segments
            if _is_curl_segment(segment)
        )
    if not cwd.is_relative_to(workspace):
        return tuple(
            _unsupported(segment, "execution_cwd_outside_workspace")
            for segment in plan.segments
            if _is_curl_segment(segment)
        )

    resolved: list[BashResolvedSubmission] = []
    for segment in plan.segments:
        if not _is_curl_segment(segment):
            continue
        static = static_by_segment.get(segment.index)
        if static is not None and static.extraction == "static_values":
            reason = _consume_values(static.submitted_values, budget)
            if reason is not None:
                resolved.append(_unsupported(segment, reason))
                continue
            resolved.append(
                BashResolvedSubmission(
                    segment_index=segment.index,
                    status="evaluated",
                    extraction="static_values",
                    submitted_values=static.submitted_values,
                )
            )
            continue
        resolved.append(
            _resolve_file_backed_segment(
                segment,
                workspace_root=workspace,
                execution_cwd=cwd,
                budget=budget,
            )
        )
    return tuple(resolved)


def _resolve_file_backed_segment(
    segment: BashSegment,
    *,
    workspace_root: Path,
    execution_cwd: Path,
    budget: _ResolutionBudget,
) -> BashResolvedSubmission:
    if any(
        not token.is_static_literal
        or (not token.is_operator and not token.value)
        for token in bash_segment_redirection_tokens(segment)
    ):
        return _unsupported(segment, "dynamic_redirection")

    words = list(bash_segment_command_tokens(segment))
    values: list[str] = []
    resolved_file = False
    index = 1
    while index < len(words):
        if time.monotonic() >= budget.deadline:
            return _unsupported(segment, "resolution_time_budget_exceeded")
        token = words[index]
        word = token.value
        if word == "--":
            break
        if not token.is_static_literal:
            return _unsupported(segment, "dynamic_curl_operand")
        if word in _KNOWN_NO_ARGUMENT_OPTIONS:
            index += 1
            continue
        if word in _KNOWN_ONE_ARGUMENT_OPTIONS:
            if index + 1 >= len(words) or not words[index + 1].is_static_literal:
                return _unsupported(segment, "dynamic_curl_option_argument")
            if word in {"-H", "--header"} and words[index + 1].value.startswith("@"):
                return _unsupported(segment, "header_file_reference_unsupported")
            index += 2
            continue
        if word.startswith("--header=@"):
            return _unsupported(segment, "header_file_reference_unsupported")
        if word.startswith("--") and any(
            word.startswith(f"{option}=")
            for option in _KNOWN_ONE_ARGUMENT_OPTIONS
            if option.startswith("--")
        ):
            index += 1
            continue
        if (
            any(
                word.startswith(prefix) and word != prefix
                for prefix in ("-A", "-H", "-m", "-o", "-x", "-X")
            )
            and not word.startswith("--")
        ):
            if word.startswith("-H@"):
                return _unsupported(segment, "header_file_reference_unsupported")
            index += 1
            continue

        operand: ShellToken | None = None
        if word == "--data-binary":
            if index + 1 >= len(words):
                return _unsupported(segment, "missing_data_binary_operand")
            operand = words[index + 1]
            index += 2
        elif word.startswith("--data-binary="):
            operand = ShellToken(
                value=word.split("=", 1)[1],
                is_operator=False,
                start=token.start,
                end=token.end,
                is_static_literal=token.is_static_literal,
            )
            index += 1
        elif word.startswith("-"):
            return _unsupported(segment, "unsupported_curl_option")
        else:
            index += 1
            continue

        if not operand.is_static_literal or not operand.value:
            return _unsupported(segment, "dynamic_or_empty_data_binary_operand")
        if operand.value.startswith("@"):
            reference = operand.value[1:]
            if reference == "-":
                return _unsupported(segment, "stdin_file_reference")
            if budget.remaining_file_references <= 0:
                return _unsupported(segment, "file_reference_limit_exceeded")
            budget.remaining_file_references -= 1
            file_value, reason = _read_workspace_file(
                reference,
                workspace_root=workspace_root,
                execution_cwd=execution_cwd,
                deadline=budget.deadline,
                remaining_total_bytes=budget.remaining_bytes,
            )
            if reason is not None:
                return _unsupported(segment, reason)
            assert file_value is not None
            value = file_value
            resolved_file = True
        else:
            value = operand.value

        reason = _consume_values((value,), budget)
        if reason is not None:
            return _unsupported(segment, reason)
        values.append(value)

    if not values or not resolved_file:
        return _unsupported(segment, "file_backed_payload_not_resolved")
    return BashResolvedSubmission(
        segment_index=segment.index,
        status="evaluated",
        extraction="resolved_file",
        submitted_values=tuple(values),
    )


def _read_workspace_file(
    reference: str,
    *,
    workspace_root: Path,
    execution_cwd: Path,
    deadline: float,
    remaining_total_bytes: int,
) -> tuple[str | None, str | None]:
    if time.monotonic() >= deadline:
        return None, "resolution_time_budget_exceeded"
    try:
        encoded_reference = reference.encode("utf-8")
    except UnicodeEncodeError:
        return None, "invalid_file_reference"
    if (
        not reference
        or len(encoded_reference) > MAX_BASH_SUBMISSION_PATH_BYTES
        or "\x00" in reference
    ):
        return None, "invalid_file_reference"

    relative = Path(reference)
    if relative.is_absolute() or ".." in relative.parts:
        return None, "file_reference_outside_workspace"
    candidate = execution_cwd / relative
    try:
        relative_to_workspace = candidate.relative_to(workspace_root)
    except ValueError:
        return None, "file_reference_outside_workspace"

    if not component_safe_file_resolution_supported():
        return None, "component_safe_open_unavailable"
    descriptor, open_reason = _open_component_safe_file(
        workspace_root,
        relative_to_workspace.parts,
    )
    if open_reason is not None:
        return None, open_reason
    assert descriptor is not None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return None, "file_reference_not_regular"
        read_limit = min(
            MAX_BASH_SUBMISSION_VALUE_BYTES,
            remaining_total_bytes,
        )
        if before.st_size > read_limit:
            return None, "resolved_payload_limit_exceeded"
        raw_parts: list[bytes] = []
        captured_bytes = 0
        while True:
            if time.monotonic() >= deadline:
                return None, "resolution_time_budget_exceeded"
            chunk = os.read(descriptor, min(8192, read_limit + 1 - captured_bytes))
            if not chunk:
                break
            raw_parts.append(chunk)
            captured_bytes += len(chunk)
            if captured_bytes > read_limit:
                return None, "resolved_payload_limit_exceeded"
        raw = b"".join(raw_parts)
        after = os.fstat(descriptor)
    except OSError:
        return None, "file_reference_unavailable"
    finally:
        os.close(descriptor)

    if time.monotonic() >= deadline:
        return None, "resolution_time_budget_exceeded"
    if len(raw) > MAX_BASH_SUBMISSION_VALUE_BYTES:
        return None, "resolved_payload_limit_exceeded"
    before_signature = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_signature = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_signature != after_signature:
        return None, "file_reference_changed_during_read"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "resolved_payload_not_utf8"
    if "\x00" in text:
        return None, "resolved_payload_not_text"
    return text, None


def component_safe_file_resolution_supported() -> bool:
    return (
        _OS_OPEN_SUPPORTS_DIR_FD
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _open_component_safe_file(
    workspace_root: Path,
    relative_parts: tuple[str, ...],
) -> tuple[int | None, str | None]:
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        return None, "invalid_file_reference"

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    opened_directories: list[int] = []
    try:
        current_directory = os.open(workspace_root, directory_flags)
        opened_directories.append(current_directory)
        for part in relative_parts[:-1]:
            try:
                current_directory = os.open(
                    part,
                    directory_flags,
                    dir_fd=current_directory,
                )
            except OSError as exc:
                return None, _component_open_error(exc, parent=True)
            opened_directories.append(current_directory)
        try:
            descriptor = os.open(
                relative_parts[-1],
                file_flags,
                dir_fd=current_directory,
            )
        except OSError as exc:
            return None, _component_open_error(exc, parent=False)
        return descriptor, None
    except FileNotFoundError:
        return None, "file_reference_missing"
    except OSError:
        return None, "file_reference_unavailable"
    finally:
        for directory in reversed(opened_directories):
            os.close(directory)


def _component_open_error(exc: OSError, *, parent: bool) -> str:
    if exc.errno == errno.ENOENT:
        return "file_reference_missing"
    if exc.errno == errno.ELOOP:
        return "file_reference_symlink"
    if exc.errno == errno.ENOTDIR:
        return (
            "file_reference_parent_not_directory"
            if parent
            else "file_reference_not_regular"
        )
    return "file_reference_unavailable"


def _consume_values(
    values: tuple[str, ...],
    budget: _ResolutionBudget,
) -> str | None:
    for value in values:
        if time.monotonic() >= budget.deadline:
            return "resolution_time_budget_exceeded"
        try:
            value_bytes = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            return "resolved_payload_not_utf8"
        if (
            value_bytes > MAX_BASH_SUBMISSION_VALUE_BYTES
            or budget.remaining_values <= 0
            or value_bytes > budget.remaining_bytes
        ):
            return "resolved_payload_limit_exceeded"
        budget.remaining_values -= 1
        budget.remaining_bytes -= value_bytes
    return None


def _unsupported(segment: BashSegment, reason: str) -> BashResolvedSubmission:
    return BashResolvedSubmission(
        segment_index=segment.index,
        status="unsupported",
        extraction="coarse_fallback",
        submitted_values=(),
        unsupported_reason=reason,
    )


def _is_curl_segment(segment: BashSegment) -> bool:
    words = list(bash_segment_command_tokens(segment))
    return bool(words and (Path(words[0].value).name or words[0].value) == "curl")
