from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from hook_monitor.analysis.adapters.registry import (
    run_adapters,
    run_adapters_incremental,
)
from hook_monitor.analysis.graph import (
    MAX_LEXICAL_CANDIDATES,
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
from hook_monitor.analysis.similarity import make_shingles
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
    load_protected_sources,
)
from hook_monitor.runtime.storage import EventStore


RUNTIME_GRAPH_DETECTOR_VERSION = "runtime-graph-v6-real-mcp-payload"


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    analysis_run: AnalysisRun
    assignments: tuple[LineageAssignment, ...]
    sinks: tuple[SinkCandidate, ...]
    mode: str


def update_runtime_analysis(
    store: EventStore,
    repo_root: Path,
    *,
    session_id: str,
    current_event_id: str,
    detector_version: str,
    minimum_path_score: float,
) -> RuntimeAnalysisResult:
    current_sequence_no = store.get_event_sequence_no(current_event_id)
    source_digest, sources, config_path = _load_source_manifest(store, repo_root)
    cursor = store.get_analysis_cursor(session_id)
    chunks = _load_source_chunks(
        store,
        repo_root,
        sources,
        config_path,
        refresh=cursor is None or cursor.source_digest != source_digest,
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
            session_id=session_id,
            current_sequence_no=current_sequence_no,
            detector_version=detector_version,
            source_digest=source_digest,
            sources=sources,
            chunks=chunks,
            minimum_path_score=minimum_path_score,
        )
    return _update_session_delta(
        store,
        repo_root,
        session_id=session_id,
        after_sequence_no=cursor.last_sequence_no,
        current_sequence_no=current_sequence_no,
        detector_version=detector_version,
        source_digest=source_digest,
        sources=sources,
        chunks=chunks,
        minimum_path_score=minimum_path_score,
    )


def _rebuild_session(
    store: EventStore,
    repo_root: Path,
    *,
    session_id: str,
    current_sequence_no: int,
    detector_version: str,
    source_digest: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
    minimum_path_score: float,
) -> RuntimeAnalysisResult:
    contexts = store.list_artifact_contexts_for_session(
        session_id,
        through_sequence_no=current_sequence_no,
    )
    adapter_result = run_adapters(contexts, repo_root)
    artifact_edges = build_artifact_flow_edges(contexts) + list(adapter_result.edges)
    source_edges = build_source_binding_edges(chunks, contexts, artifact_edges)
    source_edges += build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        repo_root,
    )
    analysis_run_id = store.start_analysis_run(
        detector_version=detector_version,
        config={
            "runtime_reanalysis": "session-full",
            "session_id": session_id,
            "through_sequence_no": current_sequence_no,
            "minimum_path_score": minimum_path_score,
        },
    )
    assignments = propagate_lineage(
        analysis_run_id,
        source_edges + artifact_edges,
        minimum_path_score=minimum_path_score,
    )

    store.clear_runtime_analysis_for_session(session_id)
    store.upsert_information_flow_edges_for_session(
        session_id,
        current_sequence_no,
        artifact_edges,
    )
    store.upsert_resource_versions(list(adapter_result.resources))
    store.upsert_sink_candidates(list(adapter_result.sinks))
    store.upsert_runtime_source_binding_edges(session_id, source_edges)
    store.replace_runtime_lineage_state(
        session_id,
        current_sequence_no,
        assignments,
    )
    _index_contexts(store, session_id, contexts)
    store.upsert_source_binding_edges(analysis_run_id, source_edges)
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)
    store.upsert_analysis_cursor(
        AnalysisCursor(
            session_id=session_id,
            detector_version=detector_version,
            source_digest=source_digest,
            last_sequence_no=current_sequence_no,
            status="ready",
        )
    )
    return RuntimeAnalysisResult(
        analysis_run=_analysis_run(store, analysis_run_id),
        assignments=tuple(assignments),
        sinks=adapter_result.sinks,
        mode="session-full",
    )


def _update_session_delta(
    store: EventStore,
    repo_root: Path,
    *,
    session_id: str,
    after_sequence_no: int,
    current_sequence_no: int,
    detector_version: str,
    source_digest: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
    minimum_path_score: float,
) -> RuntimeAnalysisResult:
    delta_contexts = store.list_artifact_contexts_for_session(
        session_id,
        after_sequence_no=after_sequence_no,
        through_sequence_no=current_sequence_no,
    )
    dependency_contexts = store.list_artifact_contexts_for_tool_uses(
        session_id,
        {
            context.tool_use_id
            for context in delta_contexts
            if context.tool_use_id is not None
        },
    )
    adapter_contexts = _deduplicate_contexts(delta_contexts + dependency_contexts)
    existing_resources = tuple(store.list_resource_versions_for_session(session_id))
    adapter_result = run_adapters_incremental(
        adapter_contexts,
        repo_root,
        existing_resources,
    )
    similarity_edges = _build_delta_similarity_edges(
        store,
        session_id,
        delta_contexts,
    )
    artifact_edges = similarity_edges + list(adapter_result.edges)
    store.upsert_information_flow_edges_for_session(
        session_id,
        current_sequence_no,
        artifact_edges,
    )
    store.upsert_resource_versions(list(adapter_result.resources))
    store.upsert_sink_candidates(list(adapter_result.sinks))

    all_artifact_edges = store.list_information_flow_edges_for_session(session_id)
    source_edges = build_source_binding_edges(
        chunks,
        delta_contexts,
        all_artifact_edges,
    )
    source_edges += build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        repo_root,
    )
    store.upsert_runtime_source_binding_edges(session_id, source_edges)

    analysis_run_id = store.start_analysis_run(
        detector_version=detector_version,
        config={
            "runtime_reanalysis": "session-incremental",
            "session_id": session_id,
            "after_sequence_no": after_sequence_no,
            "through_sequence_no": current_sequence_no,
            "minimum_path_score": minimum_path_score,
        },
    )
    existing_assignments = store.list_runtime_lineage_state(
        session_id,
        analysis_run_id,
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
    )
    assignments = store.list_runtime_lineage_state(session_id, analysis_run_id)
    runtime_source_edges = store.list_runtime_source_binding_edges(session_id)
    store.upsert_source_binding_edges(analysis_run_id, runtime_source_edges)
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)
    store.upsert_analysis_cursor(
        AnalysisCursor(
            session_id=session_id,
            detector_version=detector_version,
            source_digest=source_digest,
            last_sequence_no=current_sequence_no,
            status="ready",
        )
    )
    return RuntimeAnalysisResult(
        analysis_run=_analysis_run(store, analysis_run_id),
        assignments=tuple(assignments),
        sinks=tuple(store.list_sink_candidates_for_session(session_id)),
        mode="session-incremental",
    )


def _build_delta_similarity_edges(
    store: EventStore,
    session_id: str,
    contexts: list[ArtifactContext],
) -> list:
    edges = {}
    canonical = sorted(
        select_canonical_similarity_contexts(contexts),
        key=lambda context: (context.sequence_no, context.fragment.fragment_id),
    )
    for current in canonical:
        shingles = make_shingles(current.fragment.normalized_text)
        candidate_ids = store.find_similarity_candidate_fragment_ids(
            session_id,
            current.fragment.text_hash,
            shingles,
            current.sequence_no,
            MAX_LEXICAL_CANDIDATES,
        )
        for previous in store.list_artifact_contexts_by_fragment_ids(candidate_ids):
            edge = compare_artifact_contexts(previous, current)
            if edge is not None:
                edges[edge.edge_id] = edge
        store.upsert_fragment_shingles(
            session_id,
            [current],
            {current.fragment.fragment_id: shingles},
        )
    return list(edges.values())


def _index_contexts(
    store: EventStore,
    session_id: str,
    contexts: list[ArtifactContext],
) -> None:
    canonical = select_canonical_similarity_contexts(contexts)
    store.upsert_fragment_shingles(
        session_id,
        canonical,
        {
            context.fragment.fragment_id: make_shingles(
                context.fragment.normalized_text
            )
            for context in canonical
        },
    )


def _load_source_manifest(
    store: EventStore,
    repo_root: Path,
) -> tuple[str, list[ProtectedSource], Path | None]:
    config_path = repo_root / DEFAULT_CONFIG_PATH
    if not config_path.exists():
        sources = store.list_protected_sources()
        chunks = store.list_source_chunks()
        digest = _stored_source_digest(sources, chunks)
        return digest, sources, None

    sources = load_protected_sources(config_path)
    digest = _source_manifest_digest(config_path, repo_root, sources)
    return digest, sources, config_path


def _load_source_chunks(
    store: EventStore,
    repo_root: Path,
    sources: list[ProtectedSource],
    config_path: Path | None,
    *,
    refresh: bool,
) -> list[SourceChunk]:
    if config_path is None:
        return store.list_source_chunks()
    if refresh:
        current_sources, current_chunks = load_sources_and_chunks(
            repo_root,
            config_path,
        )
        store.upsert_sources(current_sources, current_chunks)
    active_source_ids = {source.source_id for source in sources}
    return [
        chunk
        for chunk in store.list_source_chunks()
        if chunk.source_id in active_source_ids
    ]


def _source_manifest_digest(
    config_path: Path,
    repo_root: Path,
    sources: list[ProtectedSource],
) -> str:
    digest = hashlib.sha256(config_path.read_bytes())
    for source in sorted(sources, key=lambda item: item.source_id):
        source_path = (repo_root / source.path).resolve(strict=False)
        stat = source_path.stat()
        digest.update(str(source_path).encode("utf-8"))
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
    return digest.hexdigest()


def _stored_source_digest(
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
) -> str:
    digest = hashlib.sha256()
    for source in sorted(sources, key=lambda item: item.source_id):
        digest.update(source.source_id.encode("utf-8"))
        digest.update(source.path.encode("utf-8"))
    for chunk in sorted(chunks, key=lambda item: item.chunk_id):
        digest.update(chunk.chunk_id.encode("utf-8"))
        digest.update(chunk.text_hash.encode("ascii"))
    return digest.hexdigest()


def _deduplicate_contexts(
    contexts: list[ArtifactContext],
) -> list[ArtifactContext]:
    by_id = {context.fragment.fragment_id: context for context in contexts}
    return sorted(
        by_id.values(),
        key=lambda context: (context.sequence_no, context.fragment.fragment_id),
    )


def _analysis_run(store: EventStore, analysis_run_id: str) -> AnalysisRun:
    return next(
        run
        for run in store.list_analysis_runs()
        if run.analysis_run_id == analysis_run_id
    )
