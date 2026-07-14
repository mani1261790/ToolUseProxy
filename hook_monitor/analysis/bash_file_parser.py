from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BashFileOperation:
    operation: str
    path: str
    file_descriptor: int | None
    output_is_file_content: bool = False


def parse_bash_file_operations(command: str) -> list[BashFileOperation]:
    """静的に確定できるcatとredirectionだけをfilesystem操作へ変換する。"""
    tokens = _shell_tokens(command)
    if tokens is None or not tokens:
        return []
    if any(token in {"(", ")", "<<", "<<<"} for token in tokens):
        return []

    segments = _segments(tokens)
    operations: list[BashFileOperation] = []
    simple_cat = len(segments) == 1 and not any(
        token in {"|", "||", "&&", ";", ">", ">>", "&>", "&>>"}
        for token in tokens
    )

    for segment in segments:
        operations.extend(_redirection_operations(segment))
        operations.extend(_cat_operations(segment, simple_cat=simple_cat))
    return _deduplicate(operations)


def _shell_tokens(command: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(
            command,
            posix=True,
            punctuation_chars="|&;<>()",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return None


def _segments(tokens: list[str]) -> list[list[str]]:
    separators = {"|", "||", "&&", ";"}
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in separators:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _redirection_operations(segment: list[str]) -> list[BashFileOperation]:
    operations: list[BashFileOperation] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token not in {">", ">>", "&>", "&>>", "<"}:
            index += 1
            continue
        if index + 1 >= len(segment):
            return []
        destination = segment[index + 1]
        if not _is_static_path(destination):
            index += 2
            continue

        descriptor: int | None = None
        if token.startswith("&"):
            descriptor = None
        elif index > 0 and segment[index - 1].isdigit():
            descriptor = int(segment[index - 1])
        elif token != "<":
            descriptor = 1

        operation = {
            "<": "read",
            ">": "overwrite",
            "&>": "overwrite",
            ">>": "append",
            "&>>": "append",
        }[token]
        operations.append(
            BashFileOperation(
                operation=operation,
                path=destination,
                file_descriptor=descriptor,
            )
        )
        index += 2
    return operations


def _cat_operations(
    segment: list[str],
    *,
    simple_cat: bool,
) -> list[BashFileOperation]:
    if not segment or Path(segment[0]).name != "cat":
        return []

    redirect_indexes = _redirect_operand_indexes(segment)
    operations: list[BashFileOperation] = []
    options_done = False
    for index, token in enumerate(segment[1:], start=1):
        if index in redirect_indexes:
            continue
        if token == "--" and not options_done:
            options_done = True
            continue
        if not options_done and token.startswith("-"):
            continue
        if not _is_static_path(token):
            continue
        operations.append(
            BashFileOperation(
                operation="read",
                path=token,
                file_descriptor=None,
                output_is_file_content=simple_cat,
            )
        )
    return operations


def _redirect_operand_indexes(segment: list[str]) -> set[int]:
    indexes: set[int] = set()
    for index, token in enumerate(segment):
        if token not in {">", ">>", "&>", "&>>", "<"}:
            continue
        indexes.add(index)
        if index + 1 < len(segment):
            indexes.add(index + 1)
        if index > 0 and segment[index - 1].isdigit():
            indexes.add(index - 1)
    return indexes


def _is_static_path(token: str) -> bool:
    if not token or "\0" in token:
        return False
    if any(marker in token for marker in ("$", "`", "*", "?", "[", "]")):
        return False
    if token in {"-", "&", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"}:
        return False
    if token.startswith("&") and token[1:].isdigit():
        return False
    return True


def _deduplicate(operations: list[BashFileOperation]) -> list[BashFileOperation]:
    unique: dict[tuple[str, str, int | None], BashFileOperation] = {}
    for operation in operations:
        key = (operation.operation, operation.path, operation.file_descriptor)
        existing = unique.get(key)
        if existing is None or operation.output_is_file_content:
            unique[key] = operation
    return list(unique.values())
