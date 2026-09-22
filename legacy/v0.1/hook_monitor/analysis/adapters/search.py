from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import (
    group_tool_calls,
    make_sink_candidate,
    make_submitted_to_edge,
    normalize_tool_name,
)
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate


class SearchAdapter:
    """Search query inputをexternal_search sink candidateへ変換する。"""

    name = "search"

    _SEARCH_NAMES = {
        "search",
        "web_search",
        "websearch",
        "web_search_query",
        "browser_search",
        "internet_search",
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
            if not _is_search_tool(group[0].tool_name, self._SEARCH_NAMES):
                continue
            for query_context in _select_query_contexts(group):
                sink = _make_search_sink(query_context)
                sinks[sink.node_id] = sink
                edges.append(
                    make_submitted_to_edge(
                        src_id=query_context.fragment.fragment_id,
                        sink_id=sink.node_id,
                        method="search_query",
                        reason="search query is sent to external search tool",
                    )
                )

        return AdapterResult(tuple(edges), (), tuple(sinks.values()))


def _is_search_tool(tool_name: str | None, search_names: set[str]) -> bool:
    normalized = normalize_tool_name(tool_name)
    return normalized in search_names


def _select_query_contexts(group: list[ArtifactContext]) -> list[ArtifactContext]:
    candidates = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and context.fragment.semantic_role in {"query", "search_query"}
    ]
    leaves = [context for context in candidates if context.fragment.json_pointer != "/"]
    return sorted(leaves or candidates, key=lambda context: context.fragment.fragment_id)


def _make_search_sink(context: ArtifactContext) -> SinkCandidate:
    return make_sink_candidate(
        sink_type="external_search",
        label="Search query",
        context=context,
        metadata={
            "adapter": "search",
            "query_fragment_id": context.fragment.fragment_id,
            "query_json_pointer": context.fragment.json_pointer,
        },
    )
