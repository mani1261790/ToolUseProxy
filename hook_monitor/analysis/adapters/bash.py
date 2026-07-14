from __future__ import annotations

import shlex
from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import (
    group_tool_calls,
    make_structured_edge,
    make_sink_candidate,
    make_submitted_to_edge,
    normalize_tool_name,
)
from hook_monitor.analysis.bash_file_parser import BashSegment, parse_bash_command_plan
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate
from hook_monitor.runtime.operations import bash_segment_fragment_ids


class BashAdapter:
    """Shell command inputを外部送信sink candidateへ変換する。"""

    name = "bash"

    _BASH_NAMES = {
        "bash",
        "shell",
        "exec",
        "command",
        "terminal",
        "run_command",
    }

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
                    classification = _classify_segment(
                        _basename(segment.tokens[0].value),
                        [token.value for token in segment.tokens],
                    )
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
    parents = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role == "command"
        and context.fragment.fragment_kind == "operation_container"
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
        for context in group
        if context.phase == "pre_tool_use"
        and context.fragment.fragment_kind == "bash_segment"
    }
    result: list[tuple[BashSegment, ArtifactContext]] = []
    for segment in plan.segments:
        context = contexts_by_id.get(ids[segment.index])
        if context is None:
            return None
        result.append((segment, context))
    return parent, result


def _classify_command(command: str) -> tuple[str, str, str, str] | None:
    tokens = _shell_tokens(command)
    if not tokens:
        return None

    commands = _command_segments(tokens)
    for segment in commands:
        if not segment:
            continue
        program = _basename(segment[0])
        result = _classify_segment(program, segment)
        if result is not None:
            return result
    return None


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.strip().split()


def _command_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    separators = {"|", "||", "&&", ";"}
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
