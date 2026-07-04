from __future__ import annotations

import hashlib

from hook_monitor.runtime.models import FlowEdge


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
