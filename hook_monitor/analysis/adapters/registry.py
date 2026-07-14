from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult, ToolAdapter
from hook_monitor.analysis.adapters.bash import BashAdapter
from hook_monitor.analysis.adapters.codex_final_answer import CodexFinalAnswerAdapter
from hook_monitor.analysis.adapters.filesystem import FilesystemAdapter
from hook_monitor.analysis.adapters.mcp import McpAdapter
from hook_monitor.analysis.adapters.search import SearchAdapter
from hook_monitor.runtime.models import (
    ArtifactContext,
    FlowEdge,
    ResourceVersion,
    ResourceSnapshot,
    SinkCandidate,
    ToolOperation,
)


DEFAULT_ADAPTERS: tuple[ToolAdapter, ...] = (
    FilesystemAdapter(),
    SearchAdapter(),
    BashAdapter(),
    McpAdapter(),
    CodexFinalAnswerAdapter(),
)


def run_adapters(
    contexts: list[ArtifactContext],
    repo_root: Path,
    adapters: tuple[ToolAdapter, ...] = DEFAULT_ADAPTERS,
    *,
    operations: tuple[ToolOperation, ...] = (),
    snapshots: tuple[ResourceSnapshot, ...] = (),
) -> AdapterResult:
    edges: dict[str, FlowEdge] = {}
    resources: dict[str, ResourceVersion] = {}
    sinks: dict[str, SinkCandidate] = {}
    for adapter in adapters:
        if isinstance(adapter, FilesystemAdapter):
            result = adapter.analyze_with_evidence(
                contexts,
                repo_root,
                operations,
                snapshots,
            )
        else:
            result = adapter.analyze(contexts, repo_root)
        edges.update((edge.edge_id, edge) for edge in result.edges)
        resources.update((resource.node_id, resource) for resource in result.resources)
        sinks.update((sink.node_id, sink) for sink in result.sinks)
    return AdapterResult(tuple(edges.values()), tuple(resources.values()), tuple(sinks.values()))


def run_adapters_incremental(
    contexts: list[ArtifactContext],
    repo_root: Path,
    existing_resources: tuple[ResourceVersion, ...],
    operations: tuple[ToolOperation, ...] = (),
    snapshots: tuple[ResourceSnapshot, ...] = (),
) -> AdapterResult:
    edges: dict[str, FlowEdge] = {}
    resources: dict[str, ResourceVersion] = {}
    sinks: dict[str, SinkCandidate] = {}
    for adapter in DEFAULT_ADAPTERS:
        if isinstance(adapter, FilesystemAdapter):
            result = adapter.analyze_incremental(
                contexts,
                repo_root,
                existing_resources,
                operations,
                snapshots,
            )
        else:
            result = adapter.analyze(contexts, repo_root)
        edges.update((edge.edge_id, edge) for edge in result.edges)
        resources.update((resource.node_id, resource) for resource in result.resources)
        sinks.update((sink.node_id, sink) for sink in result.sinks)
    return AdapterResult(
        tuple(edges.values()),
        tuple(resources.values()),
        tuple(sinks.values()),
    )
