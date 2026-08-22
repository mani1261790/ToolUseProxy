from __future__ import annotations

from dataclasses import dataclass

from hook_monitor.analysis.adapters.base import AdapterResult
from hook_monitor.analysis.adapters.common import (
    make_sink_candidate,
    make_submitted_to_edge,
)
from hook_monitor.runtime.models import ArtifactContext


@dataclass(frozen=True)
class ExternalityPolicyRisk:
    event_id: str
    adapter: str
    envelope_sha256: str
    verdict: str
    basis: str
    review_revision: str | None = None


def externality_policy_adapter_result(
    contexts: list[ArtifactContext],
    risk: ExternalityPolicyRisk | None,
) -> AdapterResult:
    if risk is None:
        return AdapterResult((), (), ())
    candidates = [
        context
        for context in contexts
        if context.event_id == risk.event_id
        and context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and (
            risk.adapter == "function"
            or context.fragment.semantic_role == "command"
            or context.fragment.json_pointer == "/"
        )
        and context.fragment.fragment_kind != "json_key"
    ]
    if not candidates:
        return AdapterResult((), (), ())
    segments = [
        context
        for context in candidates
        if context.fragment.fragment_kind == "bash_segment"
    ]
    selected = segments or candidates
    sinks = []
    edges = []
    for context in sorted(selected, key=lambda item: item.fragment.fragment_id):
        sink_type, label, matched_pattern = _risk_identity(risk.basis)
        sink = make_sink_candidate(
            sink_type=sink_type,
            label=label,
            context=context,
            metadata={
                "adapter": risk.adapter,
                "event_id": risk.event_id,
                "command_fragment_id": context.fragment.fragment_id,
                "matched_pattern": matched_pattern,
                "envelope_sha256": risk.envelope_sha256,
                "verdict": risk.verdict,
                "basis": risk.basis,
                **(
                    {"review_revision": risk.review_revision}
                    if risk.review_revision is not None
                    else {}
                ),
            },
        )
        sinks.append(sink)
        edges.append(
            make_submitted_to_edge(
                src_id=context.fragment.fragment_id,
                sink_id=sink.node_id,
                method=matched_pattern,
                reason=(
                    "local externality policy classifies this tool call as a "
                    "potential external sink"
                ),
            )
        )
    return AdapterResult(tuple(edges), (), tuple(sinks))


def _risk_identity(basis: str) -> tuple[str, str, str]:
    if basis == "static_external":
        return (
            "external_static_classified",
            "Statically classified external operation",
            "static_externality_rule",
        )
    if basis == "unknown_pending":
        return (
            "external_unknown_pending",
            "Unclassified operation with protected information flow",
            "conservative_unknown_externality",
        )
    if basis == "approved_rule":
        return (
            "external_rule_classified",
            "Human-approved externality rule",
            "approved_externality_rule",
        )
    if basis == "analysis_failed":
        return (
            "external_analysis_failed",
            "Externality analysis unavailable for protected information flow",
            "conservative_externality_failure",
        )
    return (
        "external_analysis_failed",
        "Externality analysis unavailable for protected information flow",
        "conservative_externality_failure",
    )
