from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import (
    group_tool_calls,
    make_structured_edge,
    make_sink_candidate,
    make_submitted_to_edge,
    normalize_tool_name,
)
from hook_monitor.analysis.bash_file_parser import (
    BashSegment,
    ShellToken,
    bash_segment_command_tokens,
    parse_bash_command_plan,
    tokenize_bash_command,
)
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate
from hook_monitor.runtime.tool_compat import SHELL_OPERATION_TOOL_NAMES
from hook_monitor.runtime.operations import bash_segment_fragment_ids


class BashAdapter:
    """Shell command inputを外部送信sink candidateへ変換する。"""

    name = "bash"

    _BASH_NAMES = SHELL_OPERATION_TOOL_NAMES

    def analyze(
        self,
        contexts: list[ArtifactContext],
        repo_root: Path,
    ) -> AdapterResult:
        del repo_root
        edges: list[FlowEdge] = []
        sinks: dict[str, SinkCandidate] = {}

        for group in group_tool_calls(contexts):
            if normalize_tool_name(group[0].tool_name) not in self._BASH_NAMES:
                continue
            planned = _planned_segment_contexts(group)
            if planned is not None:
                parent, segment_contexts = planned
                for segment, segment_context in segment_contexts:
                    if segment.connector_from == "pipe" and segment.index > 0:
                        previous_context = segment_contexts[segment.index - 1][1]
                        edges.append(
                            make_structured_edge(
                                src_kind="artifact_fragment",
                                src_id=previous_context.fragment.fragment_id,
                                dst_kind="artifact_fragment",
                                dst_id=segment_context.fragment.fragment_id,
                                relation="piped_to",
                                method="bash_pipe",
                                reason="Bash pipeline forwards stdout to the next segment",
                            )
                        )
                    command_tokens = bash_segment_command_tokens(segment)
                    if not command_tokens:
                        continue
                    classification = _classify_command(segment.text)
                    if classification is None:
                        continue
                    sink_type, label, matched_program, matched_pattern = classification
                    sink = make_sink_candidate(
                        sink_type=sink_type,
                        label=label,
                        context=segment_context,
                        metadata={
                            "adapter": "bash",
                            "event_id": segment_context.event_id,
                            "command_fragment_id": segment_context.fragment.fragment_id,
                            "command_json_pointer": segment_context.fragment.json_pointer,
                            "parent_command_fragment_id": parent.fragment.fragment_id,
                            "segment_index": segment.index,
                            "connector": segment.connector_from,
                            "matched_program": matched_program,
                            "matched_pattern": matched_pattern,
                        },
                    )
                    sinks[sink.node_id] = sink
                    edges.append(
                        make_submitted_to_edge(
                            src_id=segment_context.fragment.fragment_id,
                            sink_id=sink.node_id,
                            method="bash_segment",
                            reason=f"bash segment may send data to {sink_type}",
                        )
                    )
                continue
            for command_context in _select_command_contexts(group):
                classification = _classify_command(command_context.fragment.text)
                if classification is None:
                    continue
                sink_type, label, matched_program, matched_pattern = classification
                sink = make_sink_candidate(
                    sink_type=sink_type,
                    label=label,
                    context=command_context,
                    metadata={
                        "adapter": "bash",
                        "event_id": command_context.event_id,
                        "command_fragment_id": command_context.fragment.fragment_id,
                        "command_json_pointer": command_context.fragment.json_pointer,
                        "matched_program": matched_program,
                        "matched_pattern": matched_pattern,
                        # A rejected full plan cannot provide a trustworthy
                        # segment offset. Keep an explicit coarse identity so
                        # exact payload inspection fails closed as missing
                        # evidence instead of raising at the policy boundary.
                        "segment_index": 0,
                        "classification_scope": "coarse_command",
                    },
                )
                sinks[sink.node_id] = sink
                edges.append(
                    make_submitted_to_edge(
                        src_id=command_context.fragment.fragment_id,
                        sink_id=sink.node_id,
                        method="bash_command",
                        reason=f"bash command may send data to {sink_type}",
                    )
                )

        return AdapterResult(tuple(edges), (), tuple(sinks.values()))


def _select_command_contexts(group: list[ArtifactContext]) -> list[ArtifactContext]:
    candidates = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role == "command"
        and context.fragment.fragment_kind != "bash_segment"
    ]
    leaves = [context for context in candidates if context.fragment.json_pointer != "/"]
    return sorted(leaves or candidates, key=lambda context: context.fragment.fragment_id)


def _planned_segment_contexts(
    group: list[ArtifactContext],
) -> tuple[ArtifactContext, list[tuple[BashSegment, ArtifactContext]]] | None:
    stored_segment_contexts = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.fragment.fragment_kind == "bash_segment"
    ]
    parents = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role == "command"
        and context.fragment.fragment_kind == "operation_container"
    ]
    if not parents and stored_segment_contexts:
        parent_ids = {
            context.fragment.parent_fragment_id
            for context in stored_segment_contexts
            if context.fragment.parent_fragment_id is not None
        }
        parents = [
            context
            for context in group
            if context.phase == "pre_tool_use"
            and context.artifact_role == "tool_input"
            and context.fragment.semantic_role == "command"
            and context.fragment.fragment_id in parent_ids
        ]
    if not parents:
        return None
    parent = min(parents, key=lambda context: context.fragment.fragment_id)
    plan = parse_bash_command_plan(parent.fragment.text)
    if plan is None:
        return None
    ids = bash_segment_fragment_ids(parent.fragment, plan)
    contexts_by_id = {
        context.fragment.fragment_id: context
        for context in stored_segment_contexts
    }
    result: list[tuple[BashSegment, ArtifactContext]] = []
    for segment in plan.segments:
        context = contexts_by_id.get(ids[segment.index])
        if context is None:
            return None
        result.append((segment, context))
    return parent, result


def _classify_command(
    command: str,
    *,
    recursion_depth: int = 0,
) -> tuple[str, str, str, str] | None:
    if recursion_depth > 8:
        return None
    plan = parse_bash_command_plan(command)
    if plan is not None:
        for segment in plan.segments:
            words = [
                token.value for token in bash_segment_command_tokens(segment)
            ]
            result = _classify_words(
                words,
                direct_assignments_removed=True,
                recursion_depth=recursion_depth,
            )
            if result is not None:
                return result
    else:
        tokens = tokenize_bash_command(command)
        if not tokens:
            return None
        for segment in _command_segments(tokens):
            while segment and segment[0].is_assignment_word:
                segment.pop(0)
            result = _classify_words(
                [token.value for token in segment],
                direct_assignments_removed=True,
                recursion_depth=recursion_depth,
            )
            if result is not None:
                return result
    for nested in _nested_command_substitutions(command):
        result = _classify_command(nested, recursion_depth=recursion_depth + 1)
        if result is not None:
            return result
    return None


def classify_bash_sink_type(command: str) -> str | None:
    """Return the current adapter's sink type without materializing graph data."""
    classification = _classify_command(command)
    return None if classification is None else classification[0]


def _command_segments(tokens: tuple[ShellToken, ...]) -> list[list[ShellToken]]:
    segments: list[list[ShellToken]] = []
    current: list[ShellToken] = []
    separators = {"|", "||", "&&", ";", "\n", "&", "|&", "(", ")"}
    for token in tokens:
        if token.is_operator and token.value in separators:
            if current:
                segments.append(current)
                current = []
            continue
        if not token.is_operator:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _classify_words(
    segment: list[str],
    *,
    direct_assignments_removed: bool = False,
    recursion_depth: int = 0,
) -> tuple[str, str, str, str] | None:
    words = list(segment)
    if not direct_assignments_removed:
        while words and _is_assignment_word(words[0]):
            words.pop(0)
    while words and _basename(words[0]) in {"builtin", "command", "env"}:
        wrapper = _basename(words.pop(0))
        if wrapper == "env":
            split_command, words = _unwrap_env_arguments(words)
            if split_command is not None:
                return _classify_command(
                    split_command,
                    recursion_depth=recursion_depth + 1,
                )
            while words and _is_assignment_word(words[0]):
                words.pop(0)
        else:
            while words and words[0].startswith("-"):
                words.pop(0)
    if not words:
        return None
    program = _basename(words[0])
    if program in {"bash", "dash", "sh", "zsh"}:
        nested = _inline_shell_command(words[1:])
        return (
            None
            if nested is None
            else _classify_command(
                nested,
                recursion_depth=recursion_depth + 1,
            )
        )
    if program == "eval" and len(words) > 1:
        return _classify_command(
            " ".join(words[1:]),
            recursion_depth=recursion_depth + 1,
        )
    return _classify_segment(program, words)


def _unwrap_env_arguments(arguments: list[str]) -> tuple[str | None, list[str]]:
    words = list(arguments)
    while words:
        argument = words[0]
        if argument == "--":
            return None, words[1:]
        if argument in {"-i", "--ignore-environment", "-0", "--null"}:
            words.pop(0)
            continue
        if argument in {"-u", "--unset", "-C", "--chdir"}:
            if len(words) < 2:
                return None, []
            del words[:2]
            continue
        if argument.startswith(("--unset=", "--chdir=")):
            words.pop(0)
            continue
        if argument.startswith("-u") and argument != "-u":
            words.pop(0)
            continue
        if argument in {"-S", "--split-string"}:
            return (words[1], []) if len(words) >= 2 else (None, [])
        if argument.startswith("--split-string="):
            return argument.split("=", 1)[1], []
        break
    return None, words


def _inline_shell_command(arguments: list[str]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument in {"-c", "--command"}:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith("-") and not argument.startswith("--") and "c" in argument[1:]:
            return arguments[index + 1] if index + 1 < len(arguments) else None
    return None


def _nested_command_substitutions(command: str) -> tuple[str, ...]:
    """Return bounded shell substitutions without evaluating their content."""

    nested: list[str] = []
    quote: str | None = None
    escaped = False
    word_started = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            word_started = True
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char == "'":
            word_started = True
            if quote is None:
                quote = "'"
            elif quote == "'":
                quote = None
            index += 1
            continue
        if char == '"':
            word_started = True
            if quote is None:
                quote = '"'
            elif quote == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            index += 1
            continue
        if char == "#" and not word_started:
            while index < len(command) and command[index] not in {"\n", "\r"}:
                index += 1
            continue
        if char == "`":
            end = _find_unescaped_backtick(command, index + 1)
            if end is None:
                return tuple(nested)
            nested.append(command[index + 1 : end])
            word_started = True
            index = end + 1
            continue
        if command.startswith("$(", index) and not command.startswith("$((", index):
            end = _find_command_substitution_end(command, index + 2)
            if end is None:
                return tuple(nested)
            nested.append(command[index + 2 : end])
            word_started = True
            index = end + 1
            continue
        if char.isspace() or char in ";|&()":
            word_started = False
        else:
            word_started = True
        index += 1
    return tuple(nested)


def _find_unescaped_backtick(command: str, start: int) -> int | None:
    escaped = False
    for index in range(start, len(command)):
        char = command[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "`":
            return index
    return None


def _find_command_substitution_end(command: str, start: int) -> int | None:
    depth = 1
    quote: str | None = None
    escaped = False
    index = start
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            index += 1
            continue
        if quote is not None:
            index += 1
            continue
        if command.startswith("$(", index) and not command.startswith("$((", index):
            depth += 1
            index += 2
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _is_assignment_word(word: str) -> bool:
    name, separator, _value = word.partition("=")
    if not separator or not name:
        return False
    if name.endswith("+"):
        name = name[:-1]
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(
        character.isalnum() or character == "_" for character in name
    )


def _classify_segment(
    program: str,
    segment: list[str],
) -> tuple[str, str, str, str] | None:
    if program in {"curl", "wget", "http", "httpie"}:
        return ("external_http_request", "HTTP request", program, program)
    if program in {"scp", "sftp", "rsync", "ssh"}:
        return ("external_file_transfer", "File transfer", program, program)
    if program == "git" and len(segment) > 1 and segment[1] == "push":
        return ("external_git_publish", "Git publish", program, "git push")
    if program == "gh":
        pattern = _classify_gh(segment)
        if pattern:
            return ("external_git_publish", "GitHub publish", program, pattern)
    if _is_package_publish(program, segment):
        return ("external_package_publish", "Package publish", program, " ".join(segment[:2]))
    if _is_deploy(program, segment):
        return ("external_deploy", "Deploy", program, " ".join(segment[:2]))
    return None


def _classify_gh(segment: list[str]) -> str | None:
    if len(segment) >= 3 and segment[1] == "pr" and segment[2] == "create":
        return "gh pr create"
    if len(segment) >= 3 and segment[1] == "issue" and segment[2] == "create":
        return "gh issue create"
    if len(segment) >= 3 and segment[1] == "gist" and segment[2] == "create":
        return "gh gist create"
    if len(segment) >= 3 and segment[1] == "release" and segment[2] in {"upload", "create"}:
        return f"gh release {segment[2]}"
    return None


def _is_package_publish(program: str, segment: list[str]) -> bool:
    if program in {"npm", "pnpm"} and len(segment) > 1 and segment[1] == "publish":
        return True
    if program == "yarn" and len(segment) > 2 and segment[1] == "npm" and segment[2] == "publish":
        return True
    if program == "twine" and len(segment) > 1 and segment[1] == "upload":
        return True
    if program == "cargo" and len(segment) > 1 and segment[1] == "publish":
        return True
    if program == "docker" and len(segment) > 1 and segment[1] == "push":
        return True
    return False


def _is_deploy(program: str, segment: list[str]) -> bool:
    if program in {"wrangler", "vercel", "netlify"} and len(segment) > 1 and segment[1] == "deploy":
        return True
    if program in {"aws", "gcloud", "az"}:
        return True
    return False


def _basename(program: str) -> str:
    return program.rsplit("/", 1)[-1]
