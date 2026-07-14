from __future__ import annotations

from hook_monitor.policy.explanation import build_policy_explanation
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.models import StoredPolicyDecision
from hook_monitor.runtime.storage import EventStore


def store_policy_decision(
    store: EventStore,
    decision: PolicyDecision,
    analysis_run_id: str,
) -> None:
    explanation = build_policy_explanation(
        decision,
        db_path=store.db_path,
        analysis_run_id=analysis_run_id,
    )
    store.upsert_policy_decision(
        StoredPolicyDecision(
            decision_id=decision.decision_id,
            finding_id=decision.finding_id,
            analysis_run_id=analysis_run_id,
            hook_event=decision.hook_event,
            action=decision.action,
            severity=decision.severity,
            sink_type=decision.sink_type,
            source_node_kind=decision.source_node_kind,
            source_node_id=decision.source_node_id,
            sink_node_id=decision.sink_node_id,
            path_score=decision.path_score,
            reason=decision.reason,
            user_message=explanation.user_message,
            technical_summary=explanation.technical_summary,
            trace_command=explanation.trace_command,
            path_summary=explanation.path_summary,
        )
    )
