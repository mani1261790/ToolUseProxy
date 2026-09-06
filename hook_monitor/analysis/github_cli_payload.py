from __future__ import annotations

import re

from hook_monitor.analysis.bash_file_parser import (
    bash_segment_argv_tokens,
    bash_segment_command_tokens,
    parse_bash_command_plan,
)
from hook_monitor.runtime.models import SourceChunk


GITHUB_CLI_READ_PAYLOAD_VERSION = "github-cli-read-payload-v1"
MAX_GITHUB_CLI_ARGUMENT_BYTES = 8 * 1024

_ISSUE_NUMBER = re.compile(r"[1-9][0-9]{0,9}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_JSON_FIELDS = frozenset(
    {
        "assignees",
        "author",
        "body",
        "closed",
        "closedAt",
        "closedByPullRequests",
        "comments",
        "createdAt",
        "id",
        "isPinned",
        "labels",
        "milestone",
        "number",
        "projectCards",
        "projectItems",
        "reactionGroups",
        "state",
        "stateReason",
        "title",
        "updatedAt",
        "url",
    }
)


def verified_read_only_github_issue_view_segments(
    command: str,
    *,
    workspace_id: str,
    source_chunks: tuple[SourceChunk, ...],
) -> frozenset[int]:
    """Return narrowly verified ``gh issue view`` segment indexes.

    The accepted form is deliberately small: one command, a literal numeric
    issue identifier, optional ``--comments``, a bounded ``--json`` field list,
    and an optional literal ``--repo owner/name``. Dynamic shell values and all
    compound forms remain unresolved and therefore fail closed upstream.
    """

    plan = parse_bash_command_plan(command)
    if plan is None or len(plan.segments) != 1:
        return frozenset()
    segment = plan.segments[0]
    if segment.connector_from is not None:
        return frozenset()
    argv_tokens = bash_segment_argv_tokens(segment)
    command_tokens = bash_segment_command_tokens(segment)
    if (
        len(argv_tokens) != len(command_tokens)
        or not command_tokens
        or any(not token.is_static_literal for token in command_tokens)
        or any(token.is_operator for token in segment.tokens)
    ):
        return frozenset()
    argv = tuple(token.value for token in command_tokens)
    if len("\0".join(argv).encode("utf-8", errors="surrogatepass")) > MAX_GITHUB_CLI_ARGUMENT_BYTES:
        return frozenset()
    if len(argv) < 4 or argv[:3] != ("gh", "issue", "view"):
        return frozenset()
    submitted = _parse_issue_view_arguments(argv[3:])
    if submitted is None:
        return frozenset()
    if _contains_protected_content(
        submitted,
        workspace_id=workspace_id,
        source_chunks=source_chunks,
    ):
        return frozenset()
    return frozenset({segment.index})


def _parse_issue_view_arguments(arguments: tuple[str, ...]) -> tuple[str, ...] | None:
    issue_number: str | None = None
    submitted: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--comments":
            index += 1
            continue
        if argument in {"--json", "--repo", "-R"}:
            if index + 1 >= len(arguments):
                return None
            value = arguments[index + 1]
            if argument == "--json":
                fields = value.split(",")
                if not fields or any(field not in _JSON_FIELDS for field in fields):
                    return None
            elif _REPOSITORY.fullmatch(value) is None:
                return None
            submitted.append(value)
            index += 2
            continue
        if argument.startswith("-") or issue_number is not None:
            return None
        if _ISSUE_NUMBER.fullmatch(argument) is None:
            return None
        issue_number = argument
        submitted.append(argument)
        index += 1
    if issue_number is None:
        return None
    return tuple(submitted)


def _contains_protected_content(
    submitted: tuple[str, ...],
    *,
    workspace_id: str,
    source_chunks: tuple[SourceChunk, ...],
) -> bool:
    joined = " ".join(submitted)
    for chunk in source_chunks:
        if chunk.workspace_id != workspace_id or not chunk.text:
            continue
        if any(chunk.text == value for value in submitted):
            return True
        if len(chunk.text) >= 4 and chunk.text in joined:
            return True
    return False
