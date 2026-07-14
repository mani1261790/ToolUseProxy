from __future__ import annotations

from pathlib import Path

from hook_monitor.analysis.adapters.common import normalize_tool_name
from hook_monitor.analysis.adapters.mcp import parse_mcp_tool_name
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
from hook_monitor.runtime.models import NormalizedEvent, SinkCandidate
from hook_monitor.runtime.policy_audit import store_policy_decision
from hook_monitor.runtime.storage import EventStore


ENFORCED_BASH_TOOL_NAMES = {"bash"}
DEFAULT_PRE_TOOL_ADAPTERS = frozenset({"bash"})


def is_enforced_bash_tool(tool_name: str | None) -> bool:
    return normalize_tool_name(tool_name) in ENFORCED_BASH_TOOL_NAMES


def pre_tool_adapter(tool_name: str | None) -> str | None:
    if is_enforced_bash_tool(tool_name):
        return "bash"
    if parse_mcp_tool_name(tool_name) is not None:
        return "mcp"
    return None


def evaluate_pre_tool_hook_policy(
    store: EventStore,
    repo_root: Path,
    *,
    current_event: NormalizedEvent,
    enabled_adapters: frozenset[str] = DEFAULT_PRE_TOOL_ADAPTERS,
    minimum_path_score: float = 0.15,
    leak_min_score: float = 0.3,
) -> dict[str, object]:
    current_adapter = pre_tool_adapter(current_event.tool_name)
    if (
        current_event.session_id is None
        or current_adapter is None
        or current_adapter not in enabled_adapters
    ):
        return {}

    runtime_result = update_runtime_analysis(
        store,
        repo_root,
        session_id=current_event.session_id,
        current_event_id=current_event.event_id,
        detector_version=RUNTIME_GRAPH_DETECTOR_VERSION,
        minimum_path_score=minimum_path_score,
    )
    current_sinks = _current_external_sinks(
        list(runtime_result.sinks),
        current_event,
        store.get_event_sequence_no(current_event.event_id),
        current_adapter,
    )
    findings = detect_leaks(
        analysis_run=runtime_result.analysis_run,
        assignments=list(runtime_result.assignments),
        sink_candidates=current_sinks,
        min_score=leak_min_score,
        sink_types={sink.sink_type for sink in current_sinks},
    )
    selected = select_strongest_decision(evaluate_policy(findings), "PreToolUse")
    if selected is not None and selected.action != "allow":
        store_policy_decision(
            store,
            selected,
            runtime_result.analysis_run.analysis_run_id,
        )
    return render_codex_hook_output(
        selected,
        "PreToolUse",
        db_path=store.db_path,
    )


def _current_external_sinks(
    sinks: list[SinkCandidate],
    current_event: NormalizedEvent,
    current_sequence_no: int,
    current_adapter: str,
) -> list[SinkCandidate]:
    return [
        sink
        for sink in sinks
        if sink.sink_type.startswith("external_")
        and sink.sequence_no == current_sequence_no
        and sink.metadata.get("adapter") == current_adapter
        and sink.metadata.get("event_id") == current_event.event_id
        and (
            current_event.tool_use_id is None
            or sink.tool_use_id == current_event.tool_use_id
        )
    ]
