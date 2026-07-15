from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from hook_monitor.analysis.adapters.common import normalize_tool_name
from hook_monitor.analysis.adapters.mcp import (
    classify_mcp_sink_type,
    parse_mcp_tool_name,
)
from hook_monitor.analysis.adapters.mcp_profiles import inspect_mcp_input
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
MCP_INPUT_LIMIT_DENY_REASON = (
    "ToolUseProxy blocked this MCP call because its input exceeds bounded "
    "static-analysis limits"
)
MCP_INPUT_REJECTION_CODES = frozenset(
    {
        "field_count_exceeded",
        "input_bytes_exceeded",
        "input_not_object",
        "invalid_unicode_scalar",
        "json_envelope_bytes_exceeded",
        "json_envelope_nesting_exceeded",
        "nesting_depth_exceeded",
        "numeric_token_exceeded",
        "numeric_value_non_finite",
        "unsupported_input_type",
        "unsupported_numeric_constant",
    }
)


@dataclass(frozen=True)
class PreToolInputGuardResult:
    disposition: Literal["continue", "deny", "bypass"]
    hook_output: dict[str, object]


def render_mcp_input_limit_deny(rejection_code: str) -> dict[str, object]:
    safe_code = (
        rejection_code
        if rejection_code in MCP_INPUT_REJECTION_CODES
        else "input_rejected"
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"{MCP_INPUT_LIMIT_DENY_REASON} ({safe_code})."
            ),
        }
    }


def is_enforced_bash_tool(tool_name: str | None) -> bool:
    return normalize_tool_name(tool_name) in ENFORCED_BASH_TOOL_NAMES


def pre_tool_adapter(tool_name: str | None) -> str | None:
    if is_enforced_bash_tool(tool_name):
        return "bash"
    if parse_mcp_tool_name(tool_name) is not None:
        return "mcp"
    return None


def evaluate_pre_tool_input_bounds(
    current_event: NormalizedEvent,
    *,
    enabled_adapters: frozenset[str] = DEFAULT_PRE_TOOL_ADAPTERS,
) -> PreToolInputGuardResult:
    """Deny oversized writes and bypass oversized reads before materialization."""
    if (
        current_event.workspace_status != "ready"
        or "mcp" not in enabled_adapters
        or pre_tool_adapter(current_event.tool_name) != "mcp"
    ):
        return PreToolInputGuardResult("continue", {})
    arguments = current_event.raw_payload.get("tool_input")
    inspection = inspect_mcp_input(arguments)
    if inspection.accepted:
        return PreToolInputGuardResult("continue", {})
    classifier_payload = arguments if isinstance(arguments, dict) else {}
    if classify_mcp_sink_type(current_event.tool_name, classifier_payload) is None:
        return PreToolInputGuardResult("bypass", {})
    rejection_code = inspection.rejection_code or "input_rejected"
    return PreToolInputGuardResult(
        "deny",
        render_mcp_input_limit_deny(rejection_code),
    )


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
        or current_event.workspace_status != "ready"
        or current_event.workspace_id is None
        or current_adapter is None
        or current_adapter not in enabled_adapters
    ):
        return {}

    bounded_input_guard = evaluate_pre_tool_input_bounds(
        current_event,
        enabled_adapters=enabled_adapters,
    )
    if bounded_input_guard.disposition != "continue":
        return bounded_input_guard.hook_output

    runtime_result = update_runtime_analysis(
        store,
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
        analysis_run_id=runtime_result.analysis_run.analysis_run_id,
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
        and sink.workspace_id == current_event.workspace_id
        and sink.session_id == current_event.session_id
        and sink.metadata.get("adapter") == current_adapter
        and sink.metadata.get("event_id") == current_event.event_id
        and (
            current_event.tool_use_id is None
            or sink.tool_use_id == current_event.tool_use_id
        )
    ]
