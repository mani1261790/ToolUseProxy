from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from hook_monitor.analysis.bash_file_parser import (
    BashSegment,
    ShellToken,
    bash_segment_command_tokens,
    bash_segment_redirection_tokens,
    parse_bash_command_plan,
)


BASH_SUBMISSION_EXTRACTOR_VERSION = (
    "bash-submission-v2-static-curl-data-multiline"
)
MAX_BASH_SUBMISSION_VALUES = 32
MAX_BASH_SUBMISSION_VALUE_BYTES = 32 * 1024
MAX_BASH_SUBMISSION_TOTAL_BYTES = 128 * 1024

_PAYLOAD_LONG_OPTIONS = frozenset(
    {
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--form-string",
        "--json",
    }
)
_FILE_PREFIX_OPTIONS = frozenset(
    {
        "-d",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--json",
    }
)
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
class BashSubmissionProjection:
    segment_index: int
    extraction: Literal["static_values", "coarse_fallback"]
    submitted_values: tuple[str, ...]


def extract_bash_http_submissions(
    command: str,
) -> tuple[BashSubmissionProjection, ...]:
    """Project only statically provable curl body operands.

    The function never executes or expands shell syntax. A curl segment that
    cannot be scanned without guessing remains visible as ``coarse_fallback``
    so callers can retain the existing segment-level sink evidence.
    """
    plan = parse_bash_command_plan(command)
    if plan is None:
        return ()
    projections: list[BashSubmissionProjection] = []
    for segment in plan.segments:
        projection = _project_curl_segment(segment)
        if projection is not None:
            projections.append(projection)
    return tuple(projections)


def _project_curl_segment(
    segment: BashSegment,
) -> BashSubmissionProjection | None:
    words = list(bash_segment_command_tokens(segment))
    if not words or _basename(words[0].value) != "curl":
        return None
    if any(
        not token.is_static_literal
        or (not token.is_operator and not token.value)
        for token in bash_segment_redirection_tokens(segment)
    ):
        return _coarse_projection(segment)

    values: list[str] = []
    total_bytes = 0
    uncertain = False
    index = 1
    while index < len(words):
        token = words[index]
        word = token.value
        if word == "--":
            break
        if not token.is_static_literal:
            uncertain = True
            break
        if word in _KNOWN_NO_ARGUMENT_OPTIONS:
            index += 1
            continue
        if word in _KNOWN_ONE_ARGUMENT_OPTIONS:
            if (
                index + 1 >= len(words)
                or not words[index + 1].is_static_literal
            ):
                uncertain = True
                break
            index += 2
            continue
        if word.startswith("-X") and word != "-X" and not word.startswith("--"):
            index += 1
            continue

        option: str | None = None
        operand: ShellToken | None = None
        if word == "-d" or word in _PAYLOAD_LONG_OPTIONS:
            option = word
            if index + 1 >= len(words):
                uncertain = True
                break
            operand = words[index + 1]
            index += 2
        elif word.startswith("-d") and word != "-d" and not word.startswith("--"):
            option = "-d"
            operand = ShellToken(
                value=word[2:],
                is_operator=False,
                start=token.start,
                end=token.end,
                is_static_literal=token.is_static_literal,
            )
            index += 1
        elif word.startswith("--") and "=" in word:
            candidate, value = word.split("=", 1)
            if candidate not in _PAYLOAD_LONG_OPTIONS:
                uncertain = True
                break
            option = candidate
            operand = ShellToken(
                value=value,
                is_operator=False,
                start=token.start,
                end=token.end,
                is_static_literal=token.is_static_literal,
            )
            index += 1
        elif word.startswith("-"):
            uncertain = True
            break
        else:
            index += 1
            continue

        assert option is not None
        assert operand is not None
        if (
            not operand.is_static_literal
            or not operand.value
            or _is_file_backed_operand(option, operand.value)
        ):
            uncertain = True
            break
        try:
            value_bytes = len(operand.value.encode("utf-8"))
        except UnicodeEncodeError:
            uncertain = True
            break
        if (
            value_bytes > MAX_BASH_SUBMISSION_VALUE_BYTES
            or len(values) >= MAX_BASH_SUBMISSION_VALUES
            or total_bytes + value_bytes > MAX_BASH_SUBMISSION_TOTAL_BYTES
        ):
            uncertain = True
            break
        values.append(operand.value)
        total_bytes += value_bytes

    if uncertain or not values:
        return _coarse_projection(segment)
    return BashSubmissionProjection(
        segment_index=segment.index,
        extraction="static_values",
        submitted_values=tuple(values),
    )


def _coarse_projection(segment: BashSegment) -> BashSubmissionProjection:
    return BashSubmissionProjection(
        segment_index=segment.index,
        extraction="coarse_fallback",
        submitted_values=(),
    )


def _is_file_backed_operand(option: str, value: str) -> bool:
    if option in {"--data-raw", "--form-string"}:
        return False
    if option == "--data-urlencode":
        equals = value.find("=")
        at_sign = value.find("@")
        return at_sign >= 0 and (equals < 0 or at_sign < equals)
    return option in _FILE_PREFIX_OPTIONS and value.startswith("@")


def _basename(program: str) -> str:
    return Path(program).name or program
