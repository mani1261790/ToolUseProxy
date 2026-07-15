from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any

from hook_monitor.runtime.fragments import is_artifact_root_fragment
from hook_monitor.runtime.models import ArtifactContext, FlowEdge, SinkCandidate


def make_structured_edge(
    *,
    src_kind: str,
    src_id: str,
    dst_kind: str,
    dst_id: str,
    relation: str,
    method: str,
    reason: str,
) -> FlowEdge:
    identity = "\0".join((src_kind, src_id, dst_kind, dst_id, relation, method))
    return FlowEdge(
        edge_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        src_node_kind=src_kind,
        src_node_id=src_id,
        dst_node_kind=dst_kind,
        dst_node_id=dst_id,
        relation=relation,
        evidence_level="structured",
        method=method,
        score=1.0,
        reason=reason,
    )


def normalize_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    return normalized or None


def group_tool_calls(
    contexts: list[ArtifactContext],
) -> list[list[ArtifactContext]]:
    grouped: dict[
        tuple[str | None, str | None, str],
        list[ArtifactContext],
    ] = defaultdict(list)
    for context in contexts:
        identity = context.tool_use_id or context.event_id
        grouped[(context.workspace_id, context.session_id, identity)].append(context)
    return sorted(
        grouped.values(),
        key=lambda group: min(context.sequence_no for context in group),
    )


def tool_input_payload(group: list[ArtifactContext]) -> dict[str, Any] | None:
    roots = [
        context
        for context in group
        if context.phase == "pre_tool_use"
        and context.artifact_role == "tool_input"
        and is_artifact_root_fragment(context.fragment)
    ]
    if not roots:
        return None
    try:
        payload = json.loads(roots[0].fragment.text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def make_sink_candidate(
    *,
    sink_type: str,
    label: str,
    context: ArtifactContext,
    metadata: dict[str, object],
) -> SinkCandidate:
    identity = "\0".join(
        (
            "sink_candidate_v2",
            context.workspace_id or "legacy-unscoped",
            sink_type,
            context.session_id or "-",
            context.tool_use_id or context.event_id,
            context.fragment.fragment_id,
        )
    )
    node_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return SinkCandidate(
        node_id=node_id,
        sink_type=sink_type,
        label=label,
        tool_name=context.tool_name,
        tool_use_id=context.tool_use_id,
        session_id=context.session_id,
        sequence_no=context.sequence_no,
        metadata=metadata,
        workspace_id=context.workspace_id,
    )


def make_submitted_to_edge(
    *,
    src_id: str,
    sink_id: str,
    method: str,
    reason: str,
) -> FlowEdge:
    return make_structured_edge(
        src_kind="artifact_fragment",
        src_id=src_id,
        dst_kind="sink_candidate",
        dst_id=sink_id,
        relation="submitted_to",
        method=method,
        reason=reason,
    )
