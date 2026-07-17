from __future__ import annotations

import shlex
from pathlib import Path

from hook_monitor.policy.models import PolicyDecision, PolicyExplanation


def build_policy_explanation(
    decision: PolicyDecision,
    *,
    db_path: Path | None = None,
    analysis_run_id: str | None = None,
) -> PolicyExplanation:
    source_label = f"{decision.source_node_kind}:{decision.source_node_id}"
    sink_label = f"sink_candidate:{decision.sink_node_id}"
    trace_command = _trace_command(decision, db_path, analysis_run_id)
    return PolicyExplanation(
        decision_id=decision.decision_id,
        finding_id=decision.finding_id,
        action=decision.action,
        severity=decision.severity,
        hook_event=decision.hook_event,
        source_label=source_label,
        sink_label=sink_label,
        sink_type=decision.sink_type,
        path_score=decision.path_score,
        user_message=_user_message(decision),
        technical_summary=(
            f"source={source_label} sink={decision.sink_type} "
            f"score={decision.path_score:.2f} severity={decision.severity}"
        ),
        trace_command=trace_command,
        path_summary=(source_label, decision.sink_type),
    )


def render_hook_message(explanation: PolicyExplanation) -> str:
    return "\n".join(
        (
            explanation.user_message,
            (
                f"Source: {explanation.source_label}; "
                f"Sink: {explanation.sink_type}; "
                f"Score: {explanation.path_score:.2f}; "
                f"Severity: {explanation.severity}"
            ),
            f"Trace: {explanation.trace_command}",
        )
    )


def _user_message(decision: PolicyDecision) -> str:
    if decision.sink_type == "final_answer":
        return (
            "Protected source content appears in the final answer. "
            "Revise the final answer to remove protected details, then continue."
        )
    if decision.sink_type.startswith("external_"):
        return (
            "Protected source content would be sent to an external sink. "
            "Remove protected details from the tool input before retrying."
        )
    return (
        "Protected source content reached a policy-controlled sink. "
        "Review and remove protected details before continuing."
    )


def _trace_command(
    decision: PolicyDecision,
    db_path: Path | None,
    analysis_run_id: str | None,
) -> str:
    parts = ["tooluseproxy", "trace"]
    if db_path is not None:
        parts.extend(("--db", str(db_path)))
    if analysis_run_id is not None:
        parts.extend(("--analysis-run", analysis_run_id))
    parts.extend(("--node", f"sink_candidate:{decision.sink_node_id}"))
    return shlex.join(parts)
