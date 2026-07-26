from __future__ import annotations

import os
import stat
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


BASH_SUBMISSION_RESOLVER_VERSION = "bash-submission-resolver-v1-data-binary-file"
MAX_BASH_SUBMISSION_PATH_BYTES = 4 * 1024

_KNOWN_ONE_ARGUMENT_OPTIONS = frozenset({"-X", "--request"})
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


@dataclass(frozen=True)
class BashResolvedSubmission:
    segment_index: int
    status: Literal["evaluated", "unsupported"]
    extraction: Literal["static_values", "resolved_file", "coarse_fallback"]
    submitted_values: tuple[str, ...] = field(repr=False)
    unsupported_reason: str | None = None


def resolve_bash_http_submissions(
    command: str,
    *,
    workspace_root: Path,
    execution_cwd: Path,
) -> tuple[BashResolvedSubmission, ...]:
    """Resolve a narrow, bounded subset of file-backed curl bodies.

    The resolver never executes shell syntax or target tools. Version 1 accepts
    only static ``--data-binary @relative-file`` operands inside the workspace.
    File contents are returned only to the in-process caller and must not be
    persisted or rendered.
    """
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
            )
        )
    return tuple(resolved)


def _resolve_file_backed_segment(
    segment: BashSegment,
    *,
    workspace_root: Path,
    execution_cwd: Path,
) -> BashResolvedSubmission:
    if any(
        not token.is_static_literal
        or (not token.is_operator and not token.value)
        for token in bash_segment_redirection_tokens(segment)
    ):
        return _unsupported(segment, "dynamic_redirection")

    words = list(bash_segment_command_tokens(segment))
    values: list[str] = []
    total_bytes = 0
    resolved_file = False
    index = 1
    while index < len(words):
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
            index += 2
            continue
        if word.startswith("-X") and word != "-X" and not word.startswith("--"):
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
            file_value, reason = _read_workspace_file(
                reference,
                workspace_root=workspace_root,
                execution_cwd=execution_cwd,
            )
            if reason is not None:
                return _unsupported(segment, reason)
            assert file_value is not None
            value = file_value
            resolved_file = True
        else:
            value = operand.value

        value_bytes = len(value.encode("utf-8"))
        if (
            value_bytes > MAX_BASH_SUBMISSION_VALUE_BYTES
            or len(values) >= MAX_BASH_SUBMISSION_VALUES
            or total_bytes + value_bytes > MAX_BASH_SUBMISSION_TOTAL_BYTES
        ):
            return _unsupported(segment, "resolved_payload_limit_exceeded")
        values.append(value)
        total_bytes += value_bytes

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
) -> tuple[str | None, str | None]:
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
        candidate.relative_to(workspace_root)
    except ValueError:
        return None, "file_reference_outside_workspace"

    current = workspace_root
    candidate_mode: int | None = None
    try:
        relative_to_workspace = candidate.relative_to(workspace_root)
        for part in relative_to_workspace.parts:
            current = current / part
            candidate_mode = current.lstat().st_mode
            if stat.S_ISLNK(candidate_mode):
                return None, "file_reference_symlink"
    except FileNotFoundError:
        return None, "file_reference_missing"
    except OSError:
        return None, "file_reference_unavailable"
    if candidate_mode is None or not stat.S_ISREG(candidate_mode):
        return None, "file_reference_not_regular"

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except FileNotFoundError:
        return None, "file_reference_missing"
    except OSError:
        return None, "file_reference_unavailable"
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return None, "file_reference_not_regular"
        if before.st_size > MAX_BASH_SUBMISSION_VALUE_BYTES:
            return None, "resolved_payload_limit_exceeded"
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_BASH_SUBMISSION_VALUE_BYTES + 1)
        after = os.fstat(descriptor)
    except OSError:
        return None, "file_reference_unavailable"
    finally:
        os.close(descriptor)

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
