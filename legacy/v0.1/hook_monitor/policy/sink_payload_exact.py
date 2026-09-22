from __future__ import annotations

import hashlib

from hook_monitor.analysis.sink_payload_evidence import BashSinkPayloadEvidence
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.models import SinkCandidate


EXACT_FILE_PAYLOAD_POLICY_VERSION = "exact-external-payload-policy-v3-fail-closed"
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
    protected_source_node_ids: tuple[str, ...] = (),
) -> list[PolicyDecision]:
    """Build exact-match blocks and fail closed on unresolved sink payloads.

    An external side effect must never be allowed merely because bounded payload
    inspection could not prove what would be submitted.  Exact enforcement
    therefore has three outcomes: an evaluated public payload is allowed, an
    exact protected match is blocked, and incomplete inspection is blocked as
    unsafe-to-verify whenever the workspace has protected source content.
    """
    sinks_by_id = {sink.node_id: sink for sink in sink_candidates}
    protected_scope_id = _protected_scope_id(protected_source_node_ids)
    decisions: list[PolicyDecision] = []
    for item in evidence:
        sink = sinks_by_id.get(item.sink_node_id)
        if (
            sink is None
            or sink.sink_type != "external_http_request"
            or sink.workspace_id != item.workspace_id
        ):
            continue
        if (
            item.resolution_status != "evaluated"
            or item.comparison_status != "evaluated"
        ):
            if protected_scope_id is not None:
                decisions.append(
                    _unresolved_payload_decision(
                        analysis_run_id=analysis_run_id,
                        sink=sink,
                        protected_scope_id=protected_scope_id,
                        segment_index=item.segment_index,
                        reason=(
                            item.resolution_reason
                            or item.comparison_reason
                            or "payload_inspection_incomplete"
                        ),
                    )
                )
            continue
        if (
            item.extraction != "resolved_file"
            or item.snapshot_semantics != "pre_execution_file_snapshot"
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


def build_unresolved_external_payload_decisions(
    *,
    sink_candidates: tuple[SinkCandidate, ...],
    analysis_run_id: str,
    protected_source_node_ids: tuple[str, ...],
    reason: str,
) -> list[PolicyDecision]:
    """Fail closed when inspection itself cannot produce per-sink evidence."""

    protected_scope_id = _protected_scope_id(protected_source_node_ids)
    if protected_scope_id is None:
        return []
    decisions = [
        _unresolved_payload_decision(
            analysis_run_id=analysis_run_id,
            sink=sink,
            protected_scope_id=protected_scope_id,
            segment_index=_sink_segment_index(sink),
            reason=reason,
        )
        for sink in sink_candidates
        if sink.sink_type == "external_http_request"
        and sink.metadata.get("matched_program") == "curl"
    ]
    return sorted(decisions, key=lambda item: (item.sink_node_id, item.finding_id))


def build_unverified_external_sink_decisions(
    *,
    sink_candidates: tuple[SinkCandidate, ...],
    analysis_run_id: str,
    protected_source_node_ids: tuple[str, ...],
    verified_sink_node_ids: frozenset[str],
) -> list[PolicyDecision]:
    """Block Hook-visible external sinks without complete payload evidence."""

    protected_scope_id = _protected_scope_id(protected_source_node_ids)
    if protected_scope_id is None:
        return []
    decisions = [
        _unresolved_payload_decision(
            analysis_run_id=analysis_run_id,
            sink=sink,
            protected_scope_id=protected_scope_id,
            segment_index=_sink_segment_index(sink),
            reason="external_payload_verification_unavailable",
        )
        for sink in sink_candidates
        if sink.sink_type.startswith("external_")
        and sink.node_id not in verified_sink_node_ids
    ]
    return sorted(decisions, key=lambda item: (item.sink_node_id, item.finding_id))


def _unresolved_payload_decision(
    *,
    analysis_run_id: str,
    sink: SinkCandidate,
    protected_scope_id: str,
    segment_index: int,
    reason: str,
) -> PolicyDecision:
    finding_id = _finding_id(
        analysis_run_id=analysis_run_id,
        source_node_id=protected_scope_id,
        sink_node_id=sink.node_id,
        segment_index=segment_index,
        method=f"unresolved:{reason}",
    )
    return PolicyDecision(
        decision_id=_decision_id(finding_id),
        action="block",
        severity="critical",
        finding_id=finding_id,
        sink_type=sink.sink_type,
        source_node_kind="protected_source_scope",
        source_node_id=protected_scope_id,
        sink_node_id=sink.node_id,
        path_score=1.0,
        hook_event="PreToolUse",
        reason=(
            "block because the external payload could not be inspected "
            f"completely ({reason}) while protected sources are active"
        ),
        evidence_kind="unresolved_external_payload",
    )


def _protected_scope_id(source_node_ids: tuple[str, ...]) -> str | None:
    bounded = tuple(sorted(set(source_node_ids)))
    if not bounded:
        return None
    digest = hashlib.sha256("\0".join(bounded).encode("utf-8")).hexdigest()
    return f"scope-{digest}"


def _sink_segment_index(sink: SinkCandidate) -> int:
    segment_index = sink.metadata.get("segment_index")
    if type(segment_index) is not int or segment_index < 0:
        return 0
    return segment_index


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
