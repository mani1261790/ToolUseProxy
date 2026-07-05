from __future__ import annotations

import hashlib
from dataclasses import dataclass

from hook_monitor.runtime.models import AnalysisRun, LineageAssignment, SinkCandidate


@dataclass(frozen=True)
class LeakFinding:
    finding_id: str
    analysis_run_id: str
    source_node_kind: str
    source_node_id: str
    sink_node_id: str
    sink_type: str
    sink_label: str
    severity: str
    path_score: float
    hop_count: int
    predecessor_edge_id: str | None
    reason: str


def detect_leaks(
    *,
    analysis_run: AnalysisRun,
    assignments: list[LineageAssignment],
    sink_candidates: list[SinkCandidate],
    min_score: float = 0.3,
    sink_types: set[str] | None = None,
    included_sink_types: set[str] | None = None,
    source_filter: set[tuple[str, str]] | None = None,
) -> list[LeakFinding]:
    sinks_by_id = {sink.node_id: sink for sink in sink_candidates}
    findings: list[LeakFinding] = []

    for assignment in assignments:
        if assignment.node_kind != "sink_candidate":
            continue
        if assignment.best_path_score < min_score:
            continue
        source_key = (assignment.source_node_kind, assignment.source_node_id)
        if source_filter is not None and source_key not in source_filter:
            continue
        sink = sinks_by_id.get(assignment.node_id)
        if sink is None:
            continue
        if not _is_included_sink_type(sink.sink_type, included_sink_types):
            continue
        if sink_types is not None and sink.sink_type not in sink_types:
            continue

        findings.append(
            LeakFinding(
                finding_id=_finding_id(analysis_run.analysis_run_id, assignment, sink),
                analysis_run_id=analysis_run.analysis_run_id,
                source_node_kind=assignment.source_node_kind,
                source_node_id=assignment.source_node_id,
                sink_node_id=sink.node_id,
                sink_type=sink.sink_type,
                sink_label=sink.label,
                severity=severity_for_score(assignment.best_path_score),
                path_score=assignment.best_path_score,
                hop_count=assignment.hop_count,
                predecessor_edge_id=assignment.predecessor_edge_id,
                reason=f"source lineage reached {sink.sink_type} sink candidate",
            )
        )

    return sorted(findings, key=_finding_sort_key)


def _is_included_sink_type(
    sink_type: str,
    included_sink_types: set[str] | None,
) -> bool:
    if sink_type.startswith("external_"):
        return True
    return included_sink_types is not None and sink_type in included_sink_types


def severity_for_score(path_score: float) -> str:
    if path_score >= 0.9:
        return "critical"
    if path_score >= 0.6:
        return "high"
    if path_score >= 0.3:
        return "medium"
    return "low"


def _finding_id(
    analysis_run_id: str,
    assignment: LineageAssignment,
    sink: SinkCandidate,
) -> str:
    identity = "\0".join(
        (
            analysis_run_id,
            assignment.source_node_kind,
            assignment.source_node_id,
            sink.node_id,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _finding_sort_key(finding: LeakFinding) -> tuple[int, float, str, str]:
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    return (
        severity_order.get(finding.severity, 9),
        -finding.path_score,
        finding.source_node_id,
        finding.sink_node_id,
    )
