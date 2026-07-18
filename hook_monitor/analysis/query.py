from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hook_monitor.runtime.models import (
    AnalysisRun,
    ArtifactContext,
    ArtifactFragment,
    FlowEdge,
    ProtectedSource,
    ResourceVersion,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.source_config import parse_protected_source_selector
from hook_monitor.runtime.workspace import WorkspaceContext, make_workspace_id, resolve_workspace


NodeKey = tuple[str, str]


class AnalysisScopeError(ValueError):
    """Raised when an offline analysis query has no safe workspace scope."""


@dataclass(frozen=True)
class AnalysisRunScope:
    analysis_run: AnalysisRun
    workspace_id: str
    canonical_root: str
    session_id: str | None
    graph_coverage: str

    def list_artifact_contexts(self, store: EventStore) -> list[ArtifactContext]:
        if self.session_id is None:
            return [
                _artifact_context_from_snapshot(payload)
                for payload in store.list_analysis_run_node_snapshots(
                    self.analysis_run.analysis_run_id,
                    "artifact_fragment",
                )
            ]
        return store.list_artifact_contexts_for_scope(
            self.workspace_id,
            self.session_id,
        )

    def list_information_flow_edges(self, store: EventStore) -> list[FlowEdge]:
        if self.graph_coverage in {"full", "lineage"}:
            return store.list_analysis_run_flow_edges(
                self.analysis_run.analysis_run_id,
            )
        assert self.session_id is not None
        edges = store.list_information_flow_edges_for_session(
            self.session_id,
            workspace_id=self.workspace_id,
        )
        source_edges = store.list_source_binding_edges(
            self.analysis_run.analysis_run_id,
        )
        edges_by_id: dict[str, FlowEdge] = {}
        for edge in edges + source_edges:
            previous = edges_by_id.get(edge.edge_id)
            if previous is not None and previous != edge:
                raise AnalysisScopeError(
                    "Analysis run graph contains conflicting edge payloads"
                )
            edges_by_id[edge.edge_id] = edge
        return [edges_by_id[edge_id] for edge_id in sorted(edges_by_id)]

    def list_resource_versions(self, store: EventStore) -> list[ResourceVersion]:
        if self.session_id is None:
            return [
                ResourceVersion(**payload)
                for payload in store.list_analysis_run_node_snapshots(
                    self.analysis_run.analysis_run_id,
                    "resource_version",
                )
            ]
        return store.list_resource_versions_for_session(
            self.session_id,
            workspace_id=self.workspace_id,
        )

    def list_sink_candidates(self, store: EventStore) -> list[SinkCandidate]:
        if self.session_id is None:
            return [
                SinkCandidate(**payload)
                for payload in store.list_analysis_run_node_snapshots(
                    self.analysis_run.analysis_run_id,
                    "sink_candidate",
                )
            ]
        return store.list_sink_candidates_for_session(
            self.session_id,
            workspace_id=self.workspace_id,
        )

    def list_protected_sources(self, store: EventStore) -> list[ProtectedSource]:
        if self.session_id is None:
            return [
                _protected_source_from_snapshot(payload)
                for payload in store.list_analysis_run_node_snapshots(
                    self.analysis_run.analysis_run_id,
                    "protected_source",
                )
            ]
        return store.list_protected_sources_for_workspace(self.workspace_id)

    def list_source_chunks(self, store: EventStore) -> list[SourceChunk]:
        if self.session_id is None:
            return [
                SourceChunk(**payload)
                for payload in store.list_analysis_run_node_snapshots(
                    self.analysis_run.analysis_run_id,
                    "source_chunk",
                )
            ]
        return store.list_source_chunks_for_workspace(self.workspace_id)


def select_analysis_run_scope(
    store: EventStore,
    *,
    analysis_run_id: str | None,
    workspace_root: Path | None,
    latest: bool,
) -> AnalysisRunScope:
    """Select one completed, workspace-owned run without a global fallback."""
    if analysis_run_id is not None:
        if workspace_root is not None or latest:
            raise AnalysisScopeError(
                "--analysis-run cannot be combined with --workspace-root or --latest"
            )
        run = store.get_analysis_run(analysis_run_id)
        if run is None:
            raise AnalysisScopeError(f"Analysis run not found: {analysis_run_id}")
        return _validated_run_scope(store, run)

    if workspace_root is None or not latest:
        raise AnalysisScopeError(
            "Choose --analysis-run ID or --workspace-root PATH --latest."
        )
    workspace = resolve_registered_workspace(store, workspace_root)
    assert workspace.workspace_id is not None
    runs = [
        run
        for run in store.list_analysis_runs_for_workspace(
            workspace.workspace_id,
            completed_only=True,
        )
        if run.session_id is None
    ]
    if not runs:
        raise AnalysisScopeError(
            f"No completed analysis runs found for workspace: {workspace.canonical_root}"
        )
    return _validated_run_scope(store, runs[0])


def resolve_registered_workspace(
    store: EventStore,
    workspace_root: Path,
) -> WorkspaceContext:
    requested = resolve_workspace(
        str(workspace_root),
        str(workspace_root),
    )
    if (
        not requested.ready
        or requested.workspace_id is None
        or requested.canonical_root is None
    ):
        raise AnalysisScopeError(
            f"Workspace root is not eligible: {workspace_root} ({requested.status})"
        )
    registered = store.get_workspace_by_canonical_root(requested.canonical_root)
    if registered is None or registered.workspace_id != requested.workspace_id:
        raise AnalysisScopeError(
            f"Workspace is not registered in this database: {requested.canonical_root}"
        )
    return registered


def matching_source_keys(
    *,
    source_keys: set[NodeKey],
    protected_sources: dict[str, ProtectedSource],
    source_chunks: dict[str, SourceChunk],
    source: str,
) -> list[NodeKey]:
    selected_source_ids = {
        protected.source_id
        for protected in protected_sources.values()
        if source in {protected.source_id, protected.source_key}
    }
    matches: set[NodeKey] = set()
    for key in source_keys:
        kind, node_id = key
        if node_id == source or f"{kind}:{node_id}" == source:
            matches.add(key)
            continue
        if kind == "source_chunk":
            chunk = source_chunks.get(node_id)
            if chunk and (
                chunk.source_id == source
                or chunk.source_id in selected_source_ids
            ):
                matches.add(key)
        elif kind == "protected_source" and node_id in selected_source_ids:
            matches.add(key)
    return sorted(matches)


def _validated_run_scope(
    store: EventStore,
    run: AnalysisRun,
) -> AnalysisRunScope:
    if run.completed_at is None:
        raise AnalysisScopeError(
            f"Analysis run is incomplete: {run.analysis_run_id}"
        )
    if run.workspace_id is None:
        raise AnalysisScopeError(
            f"Analysis run is legacy or unscoped: {run.analysis_run_id}"
        )
    workspace = store.get_workspace(run.workspace_id)
    if (
        workspace is None
        or workspace.canonical_root is None
        or workspace.workspace_id != make_workspace_id(workspace.canonical_root)
    ):
        raise AnalysisScopeError(
            f"Analysis run workspace is not registered: {run.analysis_run_id}"
        )
    graph_coverage = store.get_analysis_run_graph_coverage(run.analysis_run_id)
    if graph_coverage not in {None, "full", "lineage"}:
        raise AnalysisScopeError(
            f"Analysis run graph coverage is invalid: {run.analysis_run_id}"
        )
    if run.session_id is None and graph_coverage is None:
        raise AnalysisScopeError(
            f"Analysis run has no immutable graph snapshot: {run.analysis_run_id}"
        )
    if run.session_id is None and not store.has_analysis_run_node_snapshot(
        run.analysis_run_id
    ):
        raise AnalysisScopeError(
            f"Analysis run has no immutable node snapshot: {run.analysis_run_id}"
        )
    return AnalysisRunScope(
        analysis_run=run,
        workspace_id=run.workspace_id,
        canonical_root=workspace.canonical_root,
        session_id=run.session_id,
        graph_coverage=graph_coverage or "mutable_session",
    )


def _artifact_context_from_snapshot(
    payload: dict[str, object],
) -> ArtifactContext:
    fragment_payload = payload["fragment"]
    if not isinstance(fragment_payload, dict):
        raise AnalysisScopeError("Analysis run artifact snapshot is invalid")
    return ArtifactContext(
        fragment=ArtifactFragment(**fragment_payload),
        artifact_role=payload["artifact_role"],
        event_id=payload["event_id"],
        phase=payload["phase"],
        session_id=payload["session_id"],
        turn_id=payload["turn_id"],
        tool_use_id=payload["tool_use_id"],
        tool_name=payload["tool_name"],
        cwd=payload["cwd"],
        sequence_no=payload["sequence_no"],
        workspace_id=payload["workspace_id"],
        workspace_root=payload["workspace_root"],
        workspace_lexical_root=payload["workspace_lexical_root"],
        workspace_execution_cwd=payload["workspace_execution_cwd"],
        workspace_status=payload["workspace_status"],
    )


def _protected_source_from_snapshot(
    payload: dict[str, object],
) -> ProtectedSource:
    policy_tags = payload["policy_tags"]
    if not isinstance(policy_tags, list) or not all(
        isinstance(tag, str) for tag in policy_tags
    ):
        raise AnalysisScopeError("Analysis run source snapshot is invalid")
    return ProtectedSource(
        source_id=payload["source_id"],
        path=payload["path"],
        source_type=payload["source_type"],
        sensitivity=payload["sensitivity"],
        policy_tags=tuple(policy_tags),
        workspace_id=payload["workspace_id"],
        source_key=payload["source_key"],
        selector=parse_protected_source_selector(
            payload.get("selector"),
            source_path=payload["path"],
            source_type=payload["source_type"],
        ),
    )
