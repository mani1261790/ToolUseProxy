from __future__ import annotations

import re
from dataclasses import dataclass
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
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_PROFILE_REGISTRY,
    McpProfileRegistry,
    McpToolProfile,
    escape_json_pointer_segment,
)
from hook_monitor.runtime.fragments import is_artifact_root_fragment
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate


_CAMEL_CASE_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
)
_READ_ONLY_PREFIXES = frozenset(
    {"fetch", "get", "list", "lookup", "read", "retrieve", "search"}
)
_UNAMBIGUOUS_MUTATION_TOKENS = frozenset(
    {"create", "publish", "send", "share", "update", "upload"}
)
_CONTEXTUAL_MUTATION_TOKENS = frozenset(
    {"comment", "message", "post", "release"}
)
_MUTATION_CONNECTORS = frozenset({"and", "or", "then"})


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

    def __init__(
        self,
        profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    ) -> None:
        self._profile_registry = profile_registry

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
            profile = (
                self._profile_registry.resolve(call.server, call.tool)
                if call.real_tool_name
                else None
            )
            sink_type = (
                profile.sink_type
                if profile is not None
                else _classify_mcp(call.server, call.tool)
            )
            if sink_type is None:
                continue
            selection = _select_profiled_argument_contexts(
                group,
                call,
                profile,
            )
            for argument_context in selection.contexts:
                relative_pointer = _relative_argument_pointer(
                    argument_context.fragment.json_pointer,
                    call.argument_pointer,
                )
                field = (
                    profile.field_for_pointer(relative_pointer)
                    if profile is not None and selection.profile_status == "matched"
                    else None
                )
                sink = make_sink_candidate(
                    sink_type=sink_type,
                    label=_sink_label(sink_type, call.server, call.tool),
                    context=argument_context,
                    metadata={
                        "adapter": "mcp",
                        "event_id": argument_context.event_id,
                        "server": call.server or "",
                        "tool": call.tool or "",
                        "argument_fragment_id": argument_context.fragment.fragment_id,
                        "argument_fragment_kind": argument_context.fragment.fragment_kind,
                        "argument_json_pointer": argument_context.fragment.json_pointer,
                        "argument_relative_json_pointer": relative_pointer,
                        "argument_field_class": (
                            field.field_class
                            if field is not None
                            else (
                                "unclassified_key"
                                if argument_context.fragment.fragment_kind == "json_key"
                                else "unclassified"
                            )
                        ),
                        "argument_redactable": (
                            field.redactable if field is not None else False
                        ),
                        "profile_id": _profile_id(
                            profile,
                            call.server,
                            call.tool,
                        ),
                        "profile_version": (
                            profile.profile_version
                            if profile is not None
                            else self._profile_registry.registry_version
                        ),
                        "profile_registry_version": (
                            self._profile_registry.registry_version
                        ),
                        "profile_status": selection.profile_status,
                        "profile_rejection_code": selection.rejection_code or "",
                        "profile_preview_eligible": bool(
                            profile is not None
                            and selection.profile_status == "matched"
                            and profile.preview_eligible
                        ),
                        "call_shape": (
                            "real_codex" if call.real_tool_name else "wrapped_legacy"
                        ),
                        "matched_rule": _matched_rule(
                            call.server,
                            call.tool,
                            sink_type,
                        ),
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


@dataclass(frozen=True)
class _ResolvedMcpCall:
    server: str | None
    tool: str | None
    arguments: dict[str, Any]
    argument_pointer: str
    real_tool_name: bool


@dataclass(frozen=True)
class _ArgumentSelection:
    contexts: tuple[ArtifactContext, ...]
    profile_status: str
    rejection_code: str | None


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


def classify_mcp_sink_type(
    tool_name: str | None,
    payload: dict[str, Any],
    profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
) -> str | None:
    """Return the outbound sink type without materializing fragments or graph nodes."""
    call = _resolve_mcp_call(tool_name, payload, McpAdapter._MCP_TOOL_NAMES)
    if call is None:
        return None
    profile = (
        profile_registry.resolve(call.server, call.tool)
        if call.real_tool_name
        else None
    )
    return profile.sink_type if profile is not None else _classify_mcp(
        call.server,
        call.tool,
    )


def _resolve_mcp_call(
    tool_name: str | None,
    payload: dict[str, Any],
    mcp_tool_names: set[str],
) -> _ResolvedMcpCall | None:
    real_name = parse_mcp_tool_name(tool_name)
    if real_name is not None:
        return _ResolvedMcpCall(real_name[0], real_name[1], payload, "", True)

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
    return _ResolvedMcpCall(
        server,
        tool,
        argument_payload,
        f"/{escape_json_pointer_segment(argument_key)}",
        False,
    )


def _classify_mcp(server: str | None, tool: str | None) -> str | None:
    normalized_server = normalize_tool_name(server) or ""
    normalized_tool = _normalize_mcp_tool_name(tool) or ""
    if not normalized_tool:
        return None
    if _is_read_only_tool_name(normalized_tool):
        return None

    if _contains_any(normalized_server, {"slack", "gmail", "mail"}):
        if _contains_token_or_phrase(
            normalized_tool,
            {"send", "post", "message", "create"},
        ):
            return "external_message"
    if _contains_any(normalized_server, {"github"}):
        if _contains_token_or_phrase(
            normalized_tool,
            {"create_issue", "create_pull_request", "create_gist", "comment", "release", "upload"},
        ):
            return "external_git_publish"
    if _contains_any(
        normalized_server,
        {"google", "drive", "docs", "sheets", "notion", "linear", "jira"},
    ):
        if _contains_token_or_phrase(
            normalized_tool,
            {"create", "update", "comment", "share", "send", "upload"},
        ):
            return "external_api_call"
    if _contains_token_or_phrase(
        normalized_tool,
        {"send", "post", "create", "update", "upload", "publish", "share", "comment"},
    ):
        return "external_api_call"
    return None


def _select_profiled_argument_contexts(
    group: list[ArtifactContext],
    call: _ResolvedMcpCall,
    profile: McpToolProfile | None,
) -> _ArgumentSelection:
    fallback_contexts = _select_all_argument_contexts(
        group,
        call.argument_pointer,
    )
    if profile is None:
        return _ArgumentSelection(
            tuple(fallback_contexts),
            "unprofiled",
            "unknown_profile",
        )

    validation = profile.validate(call.arguments)
    if not validation.accepted:
        return _ArgumentSelection(
            tuple(fallback_contexts),
            "shape_rejected",
            validation.rejection_code,
        )

    wanted_pointers = {
        _absolute_argument_pointer(
            call.argument_pointer,
            f"/{escape_json_pointer_segment(str(key))}",
        )
        for key in call.arguments
    }
    contexts = sorted(
        [
            context
            for context in fallback_contexts
            if context.fragment.fragment_kind == "payload"
            and context.fragment.json_pointer in wanted_pointers
        ],
        key=lambda context: context.fragment.fragment_id,
    )
    if {context.fragment.json_pointer for context in contexts} != wanted_pointers:
        return _ArgumentSelection(
            tuple(fallback_contexts),
            "fragment_incomplete",
            "unresolved_pointer",
        )
    return _ArgumentSelection(tuple(contexts), "matched", None)


def _select_all_argument_contexts(
    group: list[ArtifactContext],
    argument_pointer: str,
) -> list[ArtifactContext]:
    contexts = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.fragment_kind in {"payload", "json_key"}
        and not is_artifact_root_fragment(context.fragment)
        and _is_argument_leaf_pointer(
            context.fragment.json_pointer,
            argument_pointer,
        )
    ]
    return sorted(contexts, key=lambda context: context.fragment.fragment_id)


def _is_argument_leaf_pointer(pointer: str, argument_pointer: str) -> bool:
    if not argument_pointer:
        return True
    return pointer.startswith(f"{argument_pointer}/")


def _absolute_argument_pointer(argument_pointer: str, relative_pointer: str) -> str:
    return f"{argument_pointer}{relative_pointer}" if argument_pointer else relative_pointer


def _relative_argument_pointer(pointer: str, argument_pointer: str) -> str:
    if not argument_pointer:
        return pointer
    return pointer[len(argument_pointer) :]


def _profile_id(
    profile: McpToolProfile | None,
    server: str | None,
    tool: str | None,
) -> str:
    if profile is not None:
        return profile.profile_id
    return f"unprofiled:{server or 'unknown_server'}/{tool or 'unknown_tool'}"


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


def _contains_token_or_phrase(value: str, needles: set[str]) -> bool:
    padded = f"_{value}_"
    return any(f"_{needle}_" in padded for needle in needles)


def _is_read_only_tool_name(value: str) -> bool:
    tokens = value.split("_")
    if not tokens or tokens[0] not in _READ_ONLY_PREFIXES:
        return False
    if any(token in _UNAMBIGUOUS_MUTATION_TOKENS for token in tokens[1:]):
        return False
    return not any(
        token in _CONTEXTUAL_MUTATION_TOKENS
        and index > 1
        and tokens[index - 1] in _MUTATION_CONNECTORS
        for index, token in enumerate(tokens[1:], start=1)
    )


def _normalize_mcp_tool_name(value: str | None) -> str | None:
    if not value:
        return None
    return normalize_tool_name(_CAMEL_CASE_BOUNDARY.sub("_", value))


def _sink_label(sink_type: str, server: str | None, tool: str | None) -> str:
    detail = "/".join(part for part in (server, tool) if part)
    return f"MCP {detail}" if detail else f"MCP {sink_type}"


def _matched_rule(server: str | None, tool: str | None, sink_type: str) -> str:
    return ".".join(
        part
        for part in (
            normalize_tool_name(server) or "unknown_server",
            _normalize_mcp_tool_name(tool) or "unknown_tool",
            sink_type,
        )
    )
