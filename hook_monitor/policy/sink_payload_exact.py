from __future__ import annotations

import hashlib

from hook_monitor.analysis.sink_payload_evidence import BashSinkPayloadEvidence
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.models import SinkCandidate


EXACT_FILE_PAYLOAD_POLICY_VERSION = "exact-file-payload-policy-v1"
_ENFORCED_MATCH_METHODS = frozenset(
    {
        "resolved_payload_exact",
        "resolved_payload_exact_substring",
    }
)


def build_exact_file_payload_decisions(
    evidence: tuple[BashSinkPayloadEvidence, ...],
    *,
    sink_candidates: tuple[SinkCandidate, ...],
    analysis_run_id: str,
) -> list[PolicyDecision]:
    """Build block decisions only from evaluated resolved-file exact evidence."""
    sinks_by_id = {sink.node_id: sink for sink in sink_candidates}
    decisions: list[PolicyDecision] = []
    for item in evidence:
        if (
            item.resolution_status != "evaluated"
            or item.comparison_status != "evaluated"
            or item.extraction != "resolved_file"
            or item.snapshot_semantics != "pre_execution_file_snapshot"
        ):
            continue
        sink = sinks_by_id.get(item.sink_node_id)
        if (
            sink is None
            or sink.sink_type != "external_http_request"
            or sink.workspace_id != item.workspace_id
        ):
            continue
        for match in item.matches:
            if (
                match.source_node_kind != "source_chunk"
                or match.method not in _ENFORCED_MATCH_METHODS
            ):
                continue
            finding_id = _finding_id(
                analysis_run_id=analysis_run_id,
                source_node_id=match.source_node_id,
                sink_node_id=item.sink_node_id,
                segment_index=item.segment_index,
                method=match.method,
            )
            decisions.append(
                PolicyDecision(
                    decision_id=_decision_id(finding_id),
                    action="block",
                    severity="critical",
                    finding_id=finding_id,
                    sink_type=sink.sink_type,
                    source_node_kind=match.source_node_kind,
                    source_node_id=match.source_node_id,
                    sink_node_id=sink.node_id,
                    path_score=1.0,
                    hook_event="PreToolUse",
                    reason=(
                        "block because an evaluated pre-execution file payload "
                        "contains exact protected source content"
                    ),
                    evidence_kind="resolved_file_exact",
                )
            )
    return sorted(
        decisions,
        key=lambda item: (
            item.source_node_id,
            item.sink_node_id,
            item.finding_id,
        ),
    )


def _finding_id(
    *,
    analysis_run_id: str,
    source_node_id: str,
    sink_node_id: str,
    segment_index: int,
    method: str,
) -> str:
    identity = "\0".join(
        (
            EXACT_FILE_PAYLOAD_POLICY_VERSION,
            analysis_run_id,
            source_node_id,
            sink_node_id,
            str(segment_index),
            method,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _decision_id(finding_id: str) -> str:
    identity = "\0".join(
        (
            EXACT_FILE_PAYLOAD_POLICY_VERSION,
            finding_id,
            "block",
            "PreToolUse",
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
