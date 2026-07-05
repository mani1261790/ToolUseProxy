from __future__ import annotations

import hashlib

from hook_monitor.analysis.leak_detection import LeakFinding
from hook_monitor.policy.models import PolicyDecision


_BLOCK_ON_CRITICAL = {
    "external_http_request",
    "external_message",
    "external_git_publish",
    "external_package_publish",
    "external_deploy",
    "external_search",
    "external_api_call",
    "external_file_transfer",
}


def evaluate_policy(findings: list[LeakFinding]) -> list[PolicyDecision]:
    return sorted(
        (_decision_for_finding(finding) for finding in findings),
        key=_decision_sort_key,
    )


def _decision_for_finding(finding: LeakFinding) -> PolicyDecision:
    action = _action_for_finding(finding)
    hook_event = _hook_event_for_sink_type(finding.sink_type)
    return PolicyDecision(
        decision_id=_decision_id(finding, action, hook_event),
        action=action,
        severity=finding.severity,
        finding_id=finding.finding_id,
        sink_type=finding.sink_type,
        source_node_kind=finding.source_node_kind,
        source_node_id=finding.source_node_id,
        sink_node_id=finding.sink_node_id,
        path_score=finding.path_score,
        hook_event=hook_event,
        reason=_reason_for_decision(action, finding),
    )


def _action_for_finding(finding: LeakFinding) -> str:
    if finding.sink_type == "final_answer":
        if finding.severity == "critical":
            return "continue_review"
        if finding.severity == "high":
            return "warn"
        return "allow"
    if finding.sink_type in _BLOCK_ON_CRITICAL:
        if finding.severity == "critical":
            return "block"
        if finding.severity == "high":
            return "warn"
        return "allow"
    if finding.severity in {"critical", "high"}:
        return "warn"
    return "allow"


def _hook_event_for_sink_type(sink_type: str) -> str | None:
    if sink_type == "final_answer":
        return "Stop"
    if sink_type.startswith("external_"):
        return "PreToolUse"
    return None


def _reason_for_decision(action: str, finding: LeakFinding) -> str:
    return (
        f"{action} because {finding.severity} source lineage reached "
        f"{finding.sink_type} sink candidate"
    )


def _decision_id(
    finding: LeakFinding,
    action: str,
    hook_event: str | None,
) -> str:
    identity = "\0".join((finding.finding_id, action, hook_event or "-"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _decision_sort_key(decision: PolicyDecision) -> tuple[int, float, str, str]:
    action_order = {
        "block": 0,
        "continue_review": 1,
        "redact": 2,
        "warn": 3,
        "allow": 4,
    }
    return (
        action_order.get(decision.action, 9),
        -decision.path_score,
        decision.source_node_id,
        decision.sink_node_id,
    )
