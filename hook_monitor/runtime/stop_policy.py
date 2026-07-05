from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.registry import run_adapters
from hook_monitor.analysis.graph import (
    build_artifact_flow_edges,
    build_protected_source_resource_edges,
    build_source_binding_edges,
)
from hook_monitor.analysis.leak_detection import detect_leaks
from hook_monitor.analysis.lineage import propagate_lineage
from hook_monitor.analysis.source_index import load_sources_and_chunks
from hook_monitor.policy.codex_output import (
    render_codex_hook_output,
    select_strongest_decision,
)
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.runtime.fragments import build_artifact_fragments
from hook_monitor.runtime.models import ProtectedSource, SinkCandidate, SourceChunk
from hook_monitor.runtime.source_config import DEFAULT_CONFIG_PATH
from hook_monitor.runtime.storage import EventStore


DETECTOR_VERSION = "stop-hook-final-answer-v1"


def evaluate_stop_hook_policy(
    store: EventStore,
    repo_root: Path,
    *,
    current_event_id: str,
    minimum_path_score: float = 0.15,
    leak_min_score: float = 0.3,
) -> dict[str, object]:
    artifacts = store.list_artifacts()
    fragments = [
        fragment
        for artifact in artifacts
        for fragment in build_artifact_fragments(artifact)
    ]
    store.upsert_artifact_fragments(fragments)

    contexts = store.list_artifact_contexts()
    adapter_result = run_adapters(contexts, repo_root)
    artifact_edges = build_artifact_flow_edges(contexts) + list(adapter_result.edges)
    store.replace_resource_versions(list(adapter_result.resources))
    store.replace_sink_candidates(list(adapter_result.sinks))
    store.replace_information_flow_edges(artifact_edges)

    sources, chunks = _load_current_sources(store, repo_root)
    store.upsert_sources(sources, chunks)
    source_edges = build_source_binding_edges(chunks, contexts, artifact_edges)
    source_edges += build_protected_source_resource_edges(
        sources,
        list(adapter_result.resources),
        repo_root,
    )

    analysis_run_id = store.start_analysis_run(
        detector_version=DETECTOR_VERSION,
        config={
            "minimum_path_score": minimum_path_score,
            "leak_min_score": leak_min_score,
            "hook_event": "Stop",
            "current_event_id": current_event_id,
            "included_sink_types": ["final_answer"],
            "runtime_reanalysis": "full-local",
        },
    )
    store.upsert_source_binding_edges(analysis_run_id, source_edges)
    assignments = propagate_lineage(
        analysis_run_id,
        source_edges + artifact_edges,
        minimum_path_score=minimum_path_score,
    )
    store.upsert_lineage_assignments(assignments)
    store.complete_analysis_run(analysis_run_id)

    analysis_run = next(
        run for run in store.list_analysis_runs() if run.analysis_run_id == analysis_run_id
    )
    findings = detect_leaks(
        analysis_run=analysis_run,
        assignments=assignments,
        sink_candidates=_current_final_answer_sinks(
            list(adapter_result.sinks),
            current_event_id,
        ),
        min_score=leak_min_score,
        sink_types={"final_answer"},
        included_sink_types={"final_answer"},
    )
    decisions = evaluate_policy(findings)
    selected = select_strongest_decision(decisions, "Stop")
    return render_codex_hook_output(
        selected,
        "Stop",
        db_path=store.db_path,
    )


def _current_final_answer_sinks(
    sinks: list[SinkCandidate],
    current_event_id: str,
) -> list[SinkCandidate]:
    return [
        sink
        for sink in sinks
        if sink.sink_type == "final_answer"
        and sink.metadata.get("event_id") == current_event_id
    ]


def _load_current_sources(
    store: EventStore,
    repo_root: Path,
) -> tuple[list[ProtectedSource], list[SourceChunk]]:
    if (repo_root / DEFAULT_CONFIG_PATH).exists():
        return load_sources_and_chunks(repo_root)
    sources, chunks = load_sources_and_chunks(repo_root)
    if sources or chunks:
        return sources, chunks
    return store.list_protected_sources(), store.list_source_chunks()
