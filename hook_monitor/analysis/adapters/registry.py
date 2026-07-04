from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.base import AdapterResult, ToolAdapter
from hook_monitor.analysis.adapters.filesystem import FilesystemAdapter
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, ResourceVersion


DEFAULT_ADAPTERS: tuple[ToolAdapter, ...] = (FilesystemAdapter(),)


def run_adapters(
    contexts: list[ArtifactContext],
    repo_root: Path,
    adapters: tuple[ToolAdapter, ...] = DEFAULT_ADAPTERS,
) -> AdapterResult:
    edges: dict[str, FlowEdge] = {}
    resources: dict[str, ResourceVersion] = {}
    for adapter in adapters:
        result = adapter.analyze(contexts, repo_root)
        edges.update((edge.edge_id, edge) for edge in result.edges)
        resources.update((resource.node_id, resource) for resource in result.resources)
    return AdapterResult(tuple(edges.values()), tuple(resources.values()))
