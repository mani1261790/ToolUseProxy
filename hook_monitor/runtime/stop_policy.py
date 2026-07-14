from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.leak_detection import detect_leaks
from hook_monitor.policy.codex_output import (
    render_codex_hook_output,
    select_strongest_decision,
)
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.runtime.incremental_analysis import (
    RUNTIME_GRAPH_DETECTOR_VERSION,
    update_runtime_analysis,
)
from hook_monitor.runtime.models import SinkCandidate
from hook_monitor.runtime.policy_audit import store_policy_decision
from hook_monitor.runtime.storage import EventStore


def evaluate_stop_hook_policy(
    store: EventStore,
    repo_root: Path,
    *,
    current_event_id: str,
    minimum_path_score: float = 0.15,
    leak_min_score: float = 0.3,
) -> dict[str, object]:
    try:
        scope = store.get_runtime_analysis_scope(current_event_id)
    except (KeyError, ValueError):
        return {}
    runtime_result = update_runtime_analysis(
        store,
        current_event_id=current_event_id,
        detector_version=RUNTIME_GRAPH_DETECTOR_VERSION,
        minimum_path_score=minimum_path_score,
    )
    analysis_run = runtime_result.analysis_run
    assignments = list(runtime_result.assignments)
    sinks = list(runtime_result.sinks)

    findings = detect_leaks(
        analysis_run=analysis_run,
        assignments=assignments,
        sink_candidates=_current_final_answer_sinks(
            sinks,
            current_event_id,
            scope.workspace_id,
            scope.session_id,
        ),
        min_score=leak_min_score,
        sink_types={"final_answer"},
        included_sink_types={"final_answer"},
    )
    decisions = evaluate_policy(findings)
    selected = select_strongest_decision(decisions, "Stop")
    if selected is not None and selected.action != "allow":
        store_policy_decision(
            store,
            selected,
            analysis_run.analysis_run_id,
        )
    return render_codex_hook_output(
        selected,
        "Stop",
        db_path=store.db_path,
        analysis_run_id=analysis_run.analysis_run_id,
    )


def _current_final_answer_sinks(
    sinks: list[SinkCandidate],
    current_event_id: str,
    workspace_id: str,
    session_id: str,
) -> list[SinkCandidate]:
    return [
        sink
        for sink in sinks
        if sink.sink_type == "final_answer"
        and sink.workspace_id == workspace_id
        and sink.session_id == session_id
        and sink.metadata.get("event_id") == current_event_id
    ]
