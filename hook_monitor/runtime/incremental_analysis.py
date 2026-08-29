from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from hook_monitor.analysis.adapters.registry import (
    run_adapters,
    run_adapters_incremental,
)
from hook_monitor.analysis.adapters.externality_rule import (
    ExternalityPolicyRisk,
    externality_policy_adapter_result,
)
from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.chunking import SOURCE_CHUNKER_VERSION
from hook_monitor.analysis.bash_submission import BASH_SUBMISSION_EXTRACTOR_VERSION
from hook_monitor.analysis.graph import (
    ARTIFACT_SIMILARITY_MINIMUM_LENGTH,
    MAX_LEXICAL_CANDIDATES,
    artifact_candidate_exact_key,
    build_artifact_flow_edges,
    build_protected_source_resource_edges,
    build_source_binding_edges,
    compare_artifact_contexts,
    select_canonical_similarity_contexts,
)
from hook_monitor.analysis.lineage import (
    propagate_lineage,
    propagate_lineage_incremental,
)
from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_PROFILE_REGISTRY,
)
from hook_monitor.analysis.similarity import (
    SIMILARITY_PROFILE_VERSION,
    prepare_similarity_text,
)
from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.runtime.models import (
    AnalysisCursor,
    AnalysisRun,
    ArtifactContext,
    LineageAssignment,
    ProtectedSource,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.source_config import (
    DEFAULT_CONFIG_PATH,
    ProtectedSourceUnavailableError,
    load_protected_sources,
    protected_source_selector_payload,
    resolve_protected_source_path,
)
from hook_monitor.runtime.storage import EventStore


_MCP_PROFILE_GRAPH_VERSION = DEFAULT_MCP_PROFILE_REGISTRY.registry_version.rsplit(":", 1)[-1][:12]
RUNTIME_GRAPH_DETECTOR_VERSION = (
    f"runtime-graph-v21-{SIMILARITY_PROFILE_VERSION}-{SOURCE_CHUNKER_VERSION}-"
    f"{BASH_SUBMISSION_EXTRACTOR_VERSION}-"
    f"mcp-profiles-{_MCP_PROFILE_GRAPH_VERSION}"
)


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    analysis_run: AnalysisRun
    assignments: tuple[LineageAssignment, ...]
    sinks: tuple[SinkCandidate, ...]
    source_chunks: tuple[SourceChunk, ...]
    source_digest: str
    mode: str


def update_runtime_analysis(
    store: EventStore,
    *,
    current_event_id: str,
    detector_version: str,
    minimum_path_score: float,
    externality_policy_risk: ExternalityPolicyRisk | None = None,
) -> RuntimeAnalysisResult:
    scope = store.get_runtime_analysis_scope(current_event_id)
    repo_root = Path(scope.canonical_root)
    workspace_id = scope.workspace_id
    session_id = scope.session_id
    current_sequence_no = scope.sequence_no
    source_digest, sources, config_path = _load_source_manifest(
        store,
        repo_root,
        workspace_id,
    )
    cursor = store.get_analysis_cursor(
        session_id,
        workspace_id=workspace_id,
    )
    chunks = _load_source_chunks(
        store,
        repo_root,
        workspace_id,
        sources,
        config_path,
        refresh=(
            cursor is None
            or cursor.detector_version != detector_version
            or cursor.source_digest != source_digest
        ),
    )
    can_increment = (
        cursor is not None
        and cursor.status == "ready"
        and cursor.detector_version == detector_version
        and cursor.source_digest == source_digest
        and cursor.last_sequence_no <= current_sequence_no
    )
    if not can_increment:
        return _rebuild_session(
            store,
            repo_root,
            workspace_id=workspace_id,
            session_id=session_id,
            current_sequence_no=current_sequence_no,
            detector_version=detector_version,
            source_digest=source_digest,
            sources=sources,
            chunks=chunks,
            minimum_path_score=minimum_path_score,
            externality_policy_risk=externality_policy_risk,
        )
    return _update_session_delta(
        store,
        repo_root,
        workspace_id=workspace_id,
        session_id=session_id,
        after_sequence_no=cursor.last_sequence_no,
        current_sequence_no=current_sequence_no,
        detector_version=detector_version,
        source_digest=source_digest,
        sources=sources,
        chunks=chunks,
        minimum_path_score=minimum_path_score,
        externality_policy_risk=externality_policy_risk,
    )


def _rebuild_session(
    store: EventStore,
    repo_root: Path,
    *,
    workspace_id: str,
    session_id: str,
    current_sequence_no: int,
    detector_version: str,
    source_digest: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
    minimum_path_score: float,
    externality_policy_risk: ExternalityPolicyRisk | None,
) -> RuntimeAnalysisResult:
    contexts = store.list_artifact_contexts_for_scope(
        workspace_id,
        session_id,
        through_sequence_no=current_sequence_no,
    )
    operations = tuple(
        store.list_tool_operations_for_scope(
            workspace_id,
            session_id,
            through_sequence_no=current_sequence_no,
        )
    )
    snapshots = tuple(
        store.list_resource_snapshots_for_scope(
            workspace_id,
            session_id,
            through_sequence_no=current_sequence_no,
        )
    )
    adapter_result = run_adapters(
        contexts,
        repo_root,
        operations=operations,
        snapshots=snapshots,
    )
    adapter_result = _merge_adapter_results(
        adapter_result,
        externality_policy_adapter_result(contexts, externality_policy_risk),
    )
    artifact_edges = build_artifact_flow_edges(contexts) + list(adapter_result.edges)
    source_edges = build_source_binding_edges(chunks, contexts, artifact_edges)
    source_edges += build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        repo_root,
    )
    analysis_run_id = store.start_runtime_analysis_run(
        detector_version=detector_version,
        config={
            "runtime_reanalysis": "session-full",
            "session_id": session_id,
            "through_sequence_no": current_sequence_no,
            "minimum_path_score": minimum_path_score,
        },
        workspace_id=workspace_id,
        session_id=session_id,
    )
    assignments = propagate_lineage(
        analysis_run_id,
        source_edges + artifact_edges,
        minimum_path_score=minimum_path_score,
    )

    store.clear_runtime_analysis_for_session(
        session_id,
        workspace_id=workspace_id,
    )
    store.upsert_information_flow_edges_for_session(
        session_id,
        current_sequence_no,
        artifact_edges,
        workspace_id=workspace_id,
    )
    store.upsert_resource_versions(
        list(adapter_result.resources),
        workspace_id=workspace_id,
        session_id=session_id,
    )
    store.upsert_sink_candidates(
        list(adapter_result.sinks),
        workspace_id=workspace_id,
        session_id=session_id,
    )
    store.upsert_runtime_source_binding_edges(
        session_id,
        source_edges,
        workspace_id=workspace_id,
    )
    store.replace_runtime_lineage_state(
        session_id,
        current_sequence_no,
        assignments,
        workspace_id=workspace_id,
        analysis_run_id=analysis_run_id,
    )
    _index_contexts(store, workspace_id, session_id, contexts)
    store.upsert_source_binding_edges(analysis_run_id, source_edges)
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)
    store.upsert_analysis_cursor(
        AnalysisCursor(
            workspace_id=workspace_id,
            session_id=session_id,
            detector_version=detector_version,
            source_digest=source_digest,
            last_sequence_no=current_sequence_no,
            status="ready",
        )
    )
    return RuntimeAnalysisResult(
        analysis_run=_analysis_run(
            store,
            analysis_run_id,
            workspace_id,
            session_id,
        ),
        assignments=tuple(assignments),
        sinks=adapter_result.sinks,
        source_chunks=tuple(chunks),
        source_digest=source_digest,
        mode="session-full",
    )


def _update_session_delta(
    store: EventStore,
    repo_root: Path,
    *,
    workspace_id: str,
    session_id: str,
    after_sequence_no: int,
    current_sequence_no: int,
    detector_version: str,
    source_digest: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
    minimum_path_score: float,
    externality_policy_risk: ExternalityPolicyRisk | None,
) -> RuntimeAnalysisResult:
    delta_contexts = store.list_artifact_contexts_for_scope(
        workspace_id,
        session_id,
        after_sequence_no=after_sequence_no,
        through_sequence_no=current_sequence_no,
    )
    delta_operations = store.list_tool_operations_for_scope(
        workspace_id,
        session_id,
        after_sequence_no=after_sequence_no,
        through_sequence_no=current_sequence_no,
    )
    delta_snapshots = store.list_resource_snapshots_for_scope(
        workspace_id,
        session_id,
        after_sequence_no=after_sequence_no,
        through_sequence_no=current_sequence_no,
    )
    affected_tool_use_ids = {
        tool_use_id
        for tool_use_id in (
            [context.tool_use_id for context in delta_contexts]
            + [operation.tool_use_id for operation in delta_operations]
            + [snapshot.tool_use_id for snapshot in delta_snapshots]
        )
        if tool_use_id is not None
    }
    dependency_contexts = store.list_artifact_contexts_for_scope_tool_uses(
        workspace_id,
        session_id,
        affected_tool_use_ids,
        through_sequence_no=current_sequence_no,
    )
    adapter_contexts = _deduplicate_contexts(delta_contexts + dependency_contexts)
    adapter_operations = tuple(
        store.list_tool_operations_for_scope_tool_uses(
            workspace_id,
            session_id,
            affected_tool_use_ids,
            through_sequence_no=current_sequence_no,
        )
    )
    adapter_snapshots = tuple(
        store.list_resource_snapshots_for_scope_tool_uses(
            workspace_id,
            session_id,
            affected_tool_use_ids,
            through_sequence_no=current_sequence_no,
        )
    )
    existing_resources = tuple(
        store.list_resource_versions_for_session(
            session_id,
            workspace_id=workspace_id,
        )
    )
    affected_operation_ids = {operation.operation_id for operation in adapter_operations}
    existing_operation_ids = {
        resource.operation_id
        for resource in existing_resources
        if resource.operation_id is not None
    }
    if affected_operation_ids & existing_operation_ids:
        # duplicate Postまたはcursor更新前の部分保存を検出した場合だけ、
        # 同一sessionをraw evidenceから再構築して重複version/cycleを避ける。
        return _rebuild_session(
            store,
            repo_root,
            workspace_id=workspace_id,
            session_id=session_id,
            current_sequence_no=current_sequence_no,
            detector_version=detector_version,
            source_digest=source_digest,
            sources=sources,
            chunks=chunks,
            minimum_path_score=minimum_path_score,
            externality_policy_risk=externality_policy_risk,
        )
    adapter_result = run_adapters_incremental(
        adapter_contexts,
        repo_root,
        existing_resources,
        adapter_operations,
        adapter_snapshots,
    )
    adapter_result = _merge_adapter_results(
        adapter_result,
        externality_policy_adapter_result(
            adapter_contexts,
            externality_policy_risk,
        ),
    )
    similarity_edges = _build_delta_similarity_edges(
        store,
        workspace_id,
        session_id,
        delta_contexts,
    )
    artifact_edges = similarity_edges + list(adapter_result.edges)
    store.upsert_information_flow_edges_for_session(
        session_id,
        current_sequence_no,
        artifact_edges,
        workspace_id=workspace_id,
    )
    store.upsert_resource_versions(
        list(adapter_result.resources),
        workspace_id=workspace_id,
        session_id=session_id,
    )
    store.upsert_sink_candidates(
        list(adapter_result.sinks),
        workspace_id=workspace_id,
        session_id=session_id,
    )

    predecessor_fragment_ids = {
        edge.src_node_id
        for edge in similarity_edges
        if edge.src_node_kind == "artifact_fragment" and edge.dst_node_kind == "artifact_fragment"
    }
    predecessor_contexts = (
        store.list_artifact_contexts_for_scope_by_fragment_ids(
            workspace_id,
            session_id,
            predecessor_fragment_ids,
        )
        if predecessor_fragment_ids
        else []
    )
    source_binding_contexts = _deduplicate_contexts(delta_contexts + predecessor_contexts)
    source_edges = build_source_binding_edges(
        chunks,
        source_binding_contexts,
        artifact_edges,
        target_fragment_ids={context.fragment.fragment_id for context in delta_contexts},
    )
    source_edges += build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        repo_root,
    )
    store.upsert_runtime_source_binding_edges(
        session_id,
        source_edges,
        workspace_id=workspace_id,
    )

    analysis_run_id = store.start_runtime_analysis_run(
        detector_version=detector_version,
        config={
            "runtime_reanalysis": "session-incremental",
            "session_id": session_id,
            "after_sequence_no": after_sequence_no,
            "through_sequence_no": current_sequence_no,
            "minimum_path_score": minimum_path_score,
        },
        workspace_id=workspace_id,
        session_id=session_id,
    )
    existing_assignments = store.list_runtime_lineage_state(
        session_id,
        analysis_run_id,
        workspace_id=workspace_id,
    )
    changed_assignments = propagate_lineage_incremental(
        analysis_run_id,
        existing_assignments,
        source_edges + artifact_edges,
        minimum_path_score=minimum_path_score,
    )
    store.upsert_runtime_lineage_state(
        session_id,
        current_sequence_no,
        changed_assignments,
        workspace_id=workspace_id,
        analysis_run_id=analysis_run_id,
    )
    assignments = store.list_runtime_lineage_state(
        session_id,
        analysis_run_id,
        workspace_id=workspace_id,
    )
    runtime_source_edges = store.list_runtime_source_binding_edges(
        session_id,
        workspace_id=workspace_id,
    )
    store.upsert_source_binding_edges(analysis_run_id, runtime_source_edges)
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)
    store.upsert_analysis_cursor(
        AnalysisCursor(
            workspace_id=workspace_id,
            session_id=session_id,
            detector_version=detector_version,
            source_digest=source_digest,
            last_sequence_no=current_sequence_no,
            status="ready",
        )
    )
    return RuntimeAnalysisResult(
        analysis_run=_analysis_run(
            store,
            analysis_run_id,
            workspace_id,
            session_id,
        ),
        assignments=tuple(assignments),
        sinks=tuple(
            store.list_sink_candidates_for_session(
                session_id,
                workspace_id=workspace_id,
            )
        ),
        source_chunks=tuple(chunks),
        source_digest=source_digest,
        mode="session-incremental",
    )


def _merge_adapter_results(
    base: AdapterResult,
    extra: AdapterResult,
) -> AdapterResult:
    edges = {edge.edge_id: edge for edge in (*base.edges, *extra.edges)}
    resources = {
        resource.node_id: resource for resource in (*base.resources, *extra.resources)
    }
    sinks = {sink.node_id: sink for sink in (*base.sinks, *extra.sinks)}
    return AdapterResult(tuple(edges.values()), tuple(resources.values()), tuple(sinks.values()))


def _build_delta_similarity_edges(
    store: EventStore,
    workspace_id: str,
    session_id: str,
    contexts: list[ArtifactContext],
) -> list:
    edges = {}
    canonical = sorted(
        select_canonical_similarity_contexts(contexts),
        key=lambda context: (context.sequence_no, context.fragment.fragment_id),
    )
    for current in canonical:
        prepared = prepare_similarity_text(
            current.fragment.text,
            normalized_text=current.fragment.normalized_text,
        )
        exact_key = artifact_candidate_exact_key(
            current,
            prepared.primary_exact_key,
        )
        candidate_ids = store.find_similarity_candidate_fragment_ids(
            session_id,
            exact_key,
            prepared.candidate_features,
            current.sequence_no,
            MAX_LEXICAL_CANDIDATES,
            workspace_id=workspace_id,
            query_normalized_length=len(current.fragment.normalized_text),
            minimum_length=ARTIFACT_SIMILARITY_MINIMUM_LENGTH,
        )
        for previous in store.list_artifact_contexts_for_scope_by_fragment_ids(
            workspace_id,
            session_id,
            candidate_ids,
        ):
            edge = compare_artifact_contexts(previous, current)
            if edge is not None:
                edges[edge.edge_id] = edge
        store.upsert_fragment_shingles(
            session_id,
            [current],
            {current.fragment.fragment_id: set(prepared.candidate_features)},
            workspace_id=workspace_id,
            exact_keys_by_fragment={current.fragment.fragment_id: exact_key},
        )
    return list(edges.values())


def _index_contexts(
    store: EventStore,
    workspace_id: str,
    session_id: str,
    contexts: list[ArtifactContext],
) -> None:
    canonical = select_canonical_similarity_contexts(contexts)
    prepared_by_fragment = {
        context.fragment.fragment_id: prepare_similarity_text(
            context.fragment.text,
            normalized_text=context.fragment.normalized_text,
        )
        for context in canonical
    }
    store.upsert_fragment_shingles(
        session_id,
        canonical,
        {
            fragment_id: set(prepared.candidate_features)
            for fragment_id, prepared in prepared_by_fragment.items()
        },
        workspace_id=workspace_id,
        exact_keys_by_fragment={
            context.fragment.fragment_id: artifact_candidate_exact_key(
                context,
                prepared_by_fragment[context.fragment.fragment_id].primary_exact_key,
            )
            for context in canonical
        },
    )


def _load_source_manifest(
    store: EventStore,
    repo_root: Path,
    workspace_id: str,
) -> tuple[str, list[ProtectedSource], Path | None]:
    config_path = repo_root / DEFAULT_CONFIG_PATH
    if not config_path.exists():
        sources = store.list_protected_sources_for_workspace(workspace_id)
        chunks = store.list_source_chunks_for_workspace(workspace_id)
        digest = _stored_source_digest(workspace_id, sources, chunks)
        return digest, sources, None

    try:
        sources = load_protected_sources(config_path, workspace_id=workspace_id)
        digest = _source_manifest_digest(
            config_path,
            repo_root,
            workspace_id,
            sources,
        )
    except (OSError, UnicodeError, ValueError):
        raise ProtectedSourceUnavailableError(
            "protected source configuration is unavailable"
        ) from None
    return digest, sources, config_path


def _load_source_chunks(
    store: EventStore,
    repo_root: Path,
    workspace_id: str,
    sources: list[ProtectedSource],
    config_path: Path | None,
    *,
    refresh: bool,
) -> list[SourceChunk]:
    if config_path is None:
        return store.list_source_chunks_for_workspace(workspace_id)
    if refresh:
        current_sources, current_chunks = load_sources_and_chunks(
            repo_root,
            config_path,
            workspace_id=workspace_id,
        )
        store.replace_sources_for_workspace(
            workspace_id,
            current_sources,
            current_chunks,
        )
    active_source_ids = {source.source_id for source in sources}
    return [
        chunk
        for chunk in store.list_source_chunks_for_workspace(workspace_id)
        if chunk.source_id in active_source_ids
    ]


def _source_manifest_digest(
    config_path: Path,
    repo_root: Path,
    workspace_id: str,
    sources: list[ProtectedSource],
) -> str:
    digest = hashlib.sha256(b"runtime-source-manifest-v4\0")
    digest.update(SOURCE_CHUNKER_VERSION.encode("ascii"))
    digest.update(b"\0")
    digest.update(workspace_id.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(repo_root).encode("utf-8"))
    digest.update(b"\0")
    digest.update(hashlib.sha256(config_path.read_bytes()).digest())
    for source in sorted(sources, key=lambda item: item.source_id):
        source_path = resolve_protected_source_path(repo_root, source.path)
        stat = source_path.stat()
        for value in (
            source.source_id,
            source.source_key or "",
            source.path,
            source.source_type,
            source.sensitivity,
            *source.policy_tags,
            json.dumps(
                protected_source_selector_payload(source.selector),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            str(source_path),
            str(stat.st_size),
            str(stat.st_mtime_ns),
            str(stat.st_ctime_ns),
            str(stat.st_dev),
            str(stat.st_ino),
        ):
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
    return digest.hexdigest()


def _stored_source_digest(
    workspace_id: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
) -> str:
    digest = hashlib.sha256(b"runtime-stored-sources-v3\0")
    digest.update(workspace_id.encode("utf-8"))
    digest.update(b"\0")
    for source in sorted(sources, key=lambda item: item.source_id):
        for value in (
            source.source_id,
            source.source_key or "",
            source.path,
            source.source_type,
            source.sensitivity,
            *source.policy_tags,
            json.dumps(
                protected_source_selector_payload(source.selector),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        ):
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
    for chunk in sorted(chunks, key=lambda item: item.chunk_id):
        for value in (
            chunk.chunk_id,
            chunk.source_id,
            str(chunk.ordinal),
            chunk.text_hash,
        ):
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
    return digest.hexdigest()


def _deduplicate_contexts(
    contexts: list[ArtifactContext],
) -> list[ArtifactContext]:
    by_id = {context.fragment.fragment_id: context for context in contexts}
    return sorted(
        by_id.values(),
        key=lambda context: (context.sequence_no, context.fragment.fragment_id),
    )


def _analysis_run(
    store: EventStore,
    analysis_run_id: str,
    workspace_id: str,
    session_id: str,
) -> AnalysisRun:
    return store.get_runtime_analysis_run(
        analysis_run_id,
        workspace_id=workspace_id,
        session_id=session_id,
    )
