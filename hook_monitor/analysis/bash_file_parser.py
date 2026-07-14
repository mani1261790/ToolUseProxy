from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class BashFileOperation:
    operation: str
    path: str
    file_descriptor: int | None
    output_is_file_content: bool = False
    segment_index: int = 0


@dataclass(frozen=True)
class ShellToken:
    value: str
    is_operator: bool
    start: int
    end: int


@dataclass(frozen=True)
class BashSegment:
    index: int
    text: str
    connector_from: str | None
    tokens: tuple[ShellToken, ...]
    operations: tuple[BashFileOperation, ...] = ()


@dataclass(frozen=True)
class BashCommandPlan:
    segments: tuple[BashSegment, ...]


_CONNECTORS = {
    "|": "pipe",
    ";": "sequence",
    "&&": "and_then",
    "||": "or_else",
}
_UNSUPPORTED_OPERATORS = {"&", "|&", "<<", "<<<", "(", ")"}
_REDIRECTIONS = {">", ">>", "&>", "&>>", "<"}
_CWD_MUTATORS = {".", "cd", "eval", "popd", "pushd", "source"}
_COMMAND_WRAPPERS = {"builtin", "command"}
_UNSUPPORTED_COMMAND_WORDS = {
    "!",
    "{",
    "}",
    "case",
    "coproc",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "fi",
    "for",
    "function",
    "if",
    "select",
    "then",
    "time",
    "until",
    "while",
}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", flags=re.DOTALL)


def parse_bash_command_plan(command: str) -> BashCommandPlan | None:
    """理解できる静的shell構造だけをsegment付きplanへ変換する。"""
    tokens = _shell_tokens(command)
    if tokens is None or not tokens:
        return None
    if any(
        token.is_operator and token.value in _UNSUPPORTED_OPERATORS
        for token in tokens
    ):
        return None

    raw_segments: list[BashSegment] = []
    current: list[ShellToken] = []
    connector_from: str | None = None
    for token in tokens:
        connector = _CONNECTORS.get(token.value) if token.is_operator else None
        if connector is None:
            current.append(token)
            continue
        if not current:
            return None
        raw_segments.append(
            _make_segment(command, len(raw_segments), connector_from, current)
        )
        current = []
        connector_from = connector
    if not current:
        return None
    raw_segments.append(
        _make_segment(command, len(raw_segments), connector_from, current)
    )
    if any(_segment_has_unsupported_command(segment) for segment in raw_segments):
        return None

    simple_cat = len(raw_segments) == 1 and not any(
        token.is_operator and token.value in _REDIRECTIONS
        for token in raw_segments[0].tokens
    )
    segments = tuple(
        replace(
            segment,
            operations=tuple(
                _segment_file_operations(segment, simple_cat=simple_cat)
            ),
        )
        for segment in raw_segments
    )
    return BashCommandPlan(segments)


def parse_bash_file_operations(command: str) -> list[BashFileOperation]:
    """互換API。operationはsegment indexを保持し、segment間ではdedupeしない。"""
    plan = parse_bash_command_plan(command)
    if plan is None:
        return []
    return [operation for segment in plan.segments for operation in segment.operations]


def _shell_tokens(command: str) -> list[ShellToken] | None:
    if "\n" in command or "\r" in command:
        return None

    tokens: list[ShellToken] = []
    value: list[str] = []
    token_start: int | None = None
    quote: str | None = None
    escaped = False
    index = 0

    def finish(end: int) -> None:
        nonlocal value, token_start
        if token_start is None:
            return
        tokens.append(
            ShellToken(
                value="".join(value),
                is_operator=False,
                start=token_start,
                end=end,
            )
        )
        value = []
        token_start = None

    while index < len(command):
        char = command[index]
        if escaped:
            value.append(char)
            escaped = False
            index += 1
            continue
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"':
                escaped = True
            else:
                value.append(char)
            index += 1
            continue
        if char == "\\":
            if token_start is None:
                token_start = index
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            if token_start is None:
                token_start = index
            quote = char
            index += 1
            continue
        if char == "#":
            # shell commentの残りを静的operationと誤認しないよう、
            # allowlistではunquoted commentをcommand全体ごと拒否する。
            return None
        if char.isspace():
            finish(index)
            index += 1
            continue

        operator = _operator_at(command, index)
        if operator is not None:
            finish(index)
            tokens.append(
                ShellToken(
                    value=operator,
                    is_operator=True,
                    start=index,
                    end=index + len(operator),
                )
            )
            index += len(operator)
            continue

        if token_start is None:
            token_start = index
        value.append(char)
        index += 1

    if escaped or quote is not None:
        return None
    finish(len(command))
    return tokens


def _operator_at(command: str, index: int) -> str | None:
    for operator in (
        "<<<",
        "&>>",
        ">>",
        "&&",
        "||",
        "|&",
        "&>",
        "<<",
        "|",
        ";",
        ">",
        "<",
        "&",
        "(",
        ")",
    ):
        if command.startswith(operator, index):
            return operator
    return None


def _make_segment(
    command: str,
    index: int,
    connector_from: str | None,
    tokens: list[ShellToken],
) -> BashSegment:
    return BashSegment(
        index=index,
        text=command[tokens[0].start : tokens[-1].end].strip(),
        connector_from=connector_from,
        tokens=tuple(tokens),
    )


def _segment_file_operations(
    segment: BashSegment,
    *,
    simple_cat: bool,
) -> list[BashFileOperation]:
    operations = _redirection_operations(segment)
    operations.extend(_cat_operations(segment, simple_cat=simple_cat))
    return _deduplicate(operations)


def _segment_has_unsupported_command(segment: BashSegment) -> bool:
    ignored = _redirect_operand_indexes(segment.tokens)
    words: list[str] = []
    for index, token in enumerate(segment.tokens):
        if index in ignored or token.is_operator:
            continue
        if not words and _ASSIGNMENT.fullmatch(token.value):
            continue
        words.append(token.value)
    if not words:
        return False

    command_index = 0
    command = Path(words[command_index]).name or words[command_index]
    if command in _UNSUPPORTED_COMMAND_WORDS:
        return True
    if command in _COMMAND_WRAPPERS:
        command_index += 1
        while command_index < len(words) and words[command_index].startswith("-"):
            command_index += 1
        if command_index >= len(words):
            return False
        command = Path(words[command_index]).name or words[command_index]
    return command in _CWD_MUTATORS


def _redirection_operations(segment: BashSegment) -> list[BashFileOperation]:
    operations: list[BashFileOperation] = []
    tokens = segment.tokens
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.is_operator or token.value not in _REDIRECTIONS:
            index += 1
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].is_operator:
            return []
        destination = tokens[index + 1].value
        if not _is_static_path(destination):
            index += 2
            continue

        descriptor: int | None = None
        if token.value.startswith("&"):
            descriptor = None
        elif index > 0 and not tokens[index - 1].is_operator and tokens[index - 1].value.isdigit():
            descriptor = int(tokens[index - 1].value)
        elif token.value != "<":
            descriptor = 1

        operation = {
            "<": "read",
            ">": "overwrite",
            "&>": "overwrite",
            ">>": "append",
            "&>>": "append",
        }[token.value]
        operations.append(
            BashFileOperation(
                operation=operation,
                path=destination,
                file_descriptor=descriptor,
                segment_index=segment.index,
            )
        )
        index += 2
    return operations


def _cat_operations(
    segment: BashSegment,
    *,
    simple_cat: bool,
) -> list[BashFileOperation]:
    tokens = segment.tokens
    if not tokens or tokens[0].is_operator or Path(tokens[0].value).name != "cat":
        return []

    redirect_indexes = _redirect_operand_indexes(tokens)
    operations: list[BashFileOperation] = []
    options_done = False
    for index, token in enumerate(tokens[1:], start=1):
        if index in redirect_indexes or token.is_operator:
            continue
        if token.value == "--" and not options_done:
            options_done = True
            continue
        if not options_done and token.value.startswith("-"):
            continue
        if not _is_static_path(token.value):
            continue
        operations.append(
            BashFileOperation(
                operation="read",
                path=token.value,
                file_descriptor=None,
                output_is_file_content=simple_cat,
                segment_index=segment.index,
            )
        )
    return operations


def _redirect_operand_indexes(tokens: tuple[ShellToken, ...]) -> set[int]:
    indexes: set[int] = set()
    for index, token in enumerate(tokens):
        if not token.is_operator or token.value not in _REDIRECTIONS:
            continue
        indexes.add(index)
        if index + 1 < len(tokens):
            indexes.add(index + 1)
        if (
            index > 0
            and not tokens[index - 1].is_operator
            and tokens[index - 1].value.isdigit()
        ):
            indexes.add(index - 1)
    return indexes


def _is_static_path(token: str) -> bool:
    if not token or "\0" in token:
        return False
    if any(
        marker in token
        for marker in ("$", "`", "*", "?", "[", "]", "{", "}")
    ):
        return False
    if token.startswith(("~+", "~-")):
        return False
    if token in {"-", "&", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"}:
        return False
    if token.startswith("&") and token[1:].isdigit():
        return False
    return True


def _deduplicate(operations: list[BashFileOperation]) -> list[BashFileOperation]:
    unique: dict[tuple[str, str, int | None, int], BashFileOperation] = {}
    for operation in operations:
        key = (
            operation.operation,
            operation.path,
            operation.file_descriptor,
            operation.segment_index,
        )
        existing = unique.get(key)
        if existing is None or operation.output_is_file_content:
            unique[key] = operation
    return list(unique.values())
