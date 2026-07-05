from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    action: str
    severity: str
    finding_id: str
    sink_type: str
    source_node_kind: str
    source_node_id: str
    sink_node_id: str
    path_score: float
    hook_event: str | None
    reason: str


@dataclass(frozen=True)
class PolicyExplanation:
    decision_id: str
    finding_id: str
    action: str
    severity: str
    hook_event: str | None
    source_label: str
    sink_label: str
    sink_type: str
    path_score: float
    user_message: str
    technical_summary: str
    trace_command: str
    path_summary: tuple[str, ...]
