from __future__ import annotations

from pathlib import Path
from typing import Any

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import (
    group_tool_calls,
    make_sink_candidate,
    make_submitted_to_edge,
    normalize_tool_name,
    tool_input_payload,
)
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate


class McpAdapter:
    """MCP tool call inputを外部送信sink candidateへ変換する。"""

    name = "mcp"

    _MCP_TOOL_NAMES = {
        "mcp",
        "mcp_call",
        "mcp_tool_call",
        "mcp_server_tool_call",
        "mcpserver_tool_call",
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
            payload = tool_input_payload(group)
            if payload is None:
                continue
            call = _resolve_mcp_call(
                group[0].tool_name,
                payload,
                self._MCP_TOOL_NAMES,
            )
            if call is None:
                continue
            server, tool, arguments, argument_pointer = call
            sink_type = _classify_mcp(server, tool)
            if sink_type is None:
                continue
            argument_contexts = _select_argument_contexts(
                group,
                arguments,
                argument_pointer,
            )
            if not argument_contexts:
                argument_contexts = _select_tool_input_root(group)
            for argument_context in argument_contexts:
                sink = make_sink_candidate(
                    sink_type=sink_type,
                    label=_sink_label(sink_type, server, tool),
                    context=argument_context,
                    metadata={
                        "adapter": "mcp",
                        "event_id": argument_context.event_id,
                        "server": server or "",
                        "tool": tool or "",
                        "argument_fragment_id": argument_context.fragment.fragment_id,
                        "argument_json_pointer": argument_context.fragment.json_pointer,
                        "matched_rule": _matched_rule(server, tool, sink_type),
                    },
                )
                sinks[sink.node_id] = sink
                edges.append(
                    make_submitted_to_edge(
                        src_id=argument_context.fragment.fragment_id,
                        sink_id=sink.node_id,
                        method="mcp_tool_call",
                        reason=f"MCP tool call may send data to {sink_type}",
                    )
                )

        return AdapterResult(tuple(edges), (), tuple(sinks.values()))


def parse_mcp_tool_name(tool_name: str | None) -> tuple[str, str] | None:
    if not tool_name:
        return None
    parts = tool_name.split("__", 2)
    if len(parts) != 3 or parts[0].lower() != "mcp":
        return None
    server, tool = parts[1], parts[2]
    if not server or not tool:
        return None
    return server, tool


def _resolve_mcp_call(
    tool_name: str | None,
    payload: dict[str, Any],
    mcp_tool_names: set[str],
) -> tuple[str | None, str | None, dict[str, Any], str] | None:
    real_name = parse_mcp_tool_name(tool_name)
    if real_name is not None:
        return real_name[0], real_name[1], payload, ""

    normalized_tool_name = normalize_tool_name(tool_name)
    server = _first_str(
        payload,
        ("server", "server_name", "mcp_server", "mcpServer"),
    )
    tool = _first_str(
        payload,
        ("tool", "tool_name", "mcp_tool", "mcpTool", "name"),
    )
    arguments = _first_mapping_with_key(payload, ("arguments", "args", "input"))
    if arguments is None:
        return None
    if normalized_tool_name not in mcp_tool_names and (server is None or tool is None):
        return None
    argument_key, argument_payload = arguments
    return server, tool, argument_payload, f"/{argument_key}"


def _classify_mcp(server: str | None, tool: str | None) -> str | None:
    normalized_server = normalize_tool_name(server) or ""
    normalized_tool = normalize_tool_name(tool) or ""
    if not normalized_tool:
        return None

    if _contains_any(normalized_server, {"slack", "gmail", "mail"}):
        if _contains_any(normalized_tool, {"send", "post", "message", "create"}):
            return "external_message"
    if _contains_any(normalized_server, {"github"}):
        if _contains_any(
            normalized_tool,
            {"create_issue", "create_pull_request", "create_gist", "comment", "release", "upload"},
        ):
            return "external_git_publish"
    if _contains_any(
        normalized_server,
        {"google", "drive", "docs", "sheets", "notion", "linear", "jira"},
    ):
        if _contains_any(normalized_tool, {"create", "update", "comment", "share", "send", "upload"}):
            return "external_api_call"
    if _contains_any(normalized_tool, {"send", "post", "create", "update", "upload", "publish", "share", "comment"}):
        return "external_api_call"
    return None


def _select_argument_contexts(
    group: list[ArtifactContext],
    arguments: dict[str, Any],
    argument_pointer: str,
) -> list[ArtifactContext]:
    wanted_pointers = {
        f"{argument_pointer}/{key}"
        for key in _message_like_keys(arguments)
    }
    if not wanted_pointers:
        return []
    contexts = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.json_pointer in wanted_pointers
    ]
    return sorted(contexts, key=lambda context: context.fragment.fragment_id)


def _message_like_keys(arguments: dict[str, Any]) -> set[str]:
    preferred = {"content", "text", "message", "body", "description", "comment", "title", "query"}
    return {
        str(key)
        for key, value in arguments.items()
        if key in preferred and isinstance(value, (str, int, float, bool))
    }


def _select_tool_input_root(group: list[ArtifactContext]) -> list[ArtifactContext]:
    roots = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.json_pointer == "/"
    ]
    return roots[:1]


def _first_str(payload: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _first_mapping_with_key(
    payload: dict[str, Any],
    keys: tuple[str, ...],
) -> tuple[str, dict[str, Any]] | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return key, value
    return None


def _contains_any(value: str, needles: set[str]) -> bool:
    return any(needle in value for needle in needles)


def _sink_label(sink_type: str, server: str | None, tool: str | None) -> str:
    detail = "/".join(part for part in (server, tool) if part)
    return f"MCP {detail}" if detail else f"MCP {sink_type}"


def _matched_rule(server: str | None, tool: str | None, sink_type: str) -> str:
    return ".".join(
        part
        for part in (
            normalize_tool_name(server) or "unknown_server",
            normalize_tool_name(tool) or "unknown_tool",
            sink_type,
        )
    )
