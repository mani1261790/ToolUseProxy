"""Bounded, resumable review of all candidate evidence, not top-k-only omission."""

from __future__ import annotations

import json
import sqlite3

from tooluseproxy.engine.requirements import inspect, reusable

from tooluseproxy.engine.graph import GraphUnavailable, digest

REQUEST_BYTES = 384_000
REVIEW_VERSION = "all-batches-v1"


def review(db, revision, records, judge, validate, *, request_bytes=REQUEST_BYTES, evidence_context=None):
    current = records["current_call"]
    prior = records["previous_calls"]
    # Preserve the ordinary single-request path for short histories.
    if len(json.dumps(records, ensure_ascii=False).encode()) <= request_bytes:
        return inspect(records, judge, validate, {node["node_id"] for node in prior if node["completed"]}, evidence_context=evidence_context)
    base_bytes = len(json.dumps(current, ensure_ascii=False).encode()) + 4096
    if base_bytes >= request_bytes:
        raise GraphUnavailable("single_call_evidence_budget")
    batches, batch, size = [], [], base_bytes
    for node in prior:
        cost = len(json.dumps(node, ensure_ascii=False).encode()) + 2
        if cost + base_bytes > request_bytes:
            raise GraphUnavailable("single_prior_call_evidence_budget")
        if size + cost > request_bytes and batch:
            batches.append(batch)
            batch, size = [], base_bytes
        batch.append(node)
        size += cost
    if batch:
        batches.append(batch)
    with sqlite3.connect(db, timeout=5) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS graph_review_parts (
            review TEXT NOT NULL,batch TEXT NOT NULL,verdict TEXT NOT NULL,
            PRIMARY KEY(review,batch))""")
    dependencies, accesses = {}, {}
    receipts, requests = [], []
    all_complete = True
    external = False
    for index, previous in enumerate(batches):
        request = dict(
            current_call=current,
            previous_calls=previous,
            history_scope=dict(kind="partition", index=index, count=len(batches)),
        )
        key = digest([REVIEW_VERSION, request])
        with sqlite3.connect(db, timeout=5) as conn:
            cached = conn.execute(
                "SELECT verdict FROM graph_review_parts WHERE review=? AND batch=?", (revision, key)
            ).fetchone()
        if cached and (not json.loads(cached[0]).get("complete") or not reusable(json.loads(cached[0]), current)):
            cached = None
        value = validate(
            json.loads(cached[0]) if cached else inspect(request, judge, validate, {node["node_id"] for node in previous if node["completed"]}, evidence_context=evidence_context),
            {node["node_id"] for node in previous if node["completed"]},
        )
        if not cached and value["complete"]:
            with sqlite3.connect(db, timeout=5) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO graph_review_parts VALUES (?,?,?)",
                    (revision, key, json.dumps(value)),
                )
        receipts.extend(value.get("evidence_receipts", []))
        requests.extend(value.get("evidence_requests", []))
        all_complete = all_complete and value["complete"]
        external = external or value["externality"] == "external"
        for edge in value["dependencies"]:
            old = dependencies.get(edge["node_id"])
            dependencies[edge["node_id"]] = edge if old is None or old.get("selection") == edge.get("selection") else dict(edge, selection=None)
        for access in value["accesses"]:
            accesses[(access["path"], access["mode"])] = access
    # Every batch is assessed. Any unresolved batch keeps the union incomplete;
    # an empty search result or an unreviewed tail cannot become an allow.
    return dict(
        externality="external" if external else "local",
        complete=all_complete,
        reason="all recorded evidence batches reviewed; semantic inference remains model-dependent",
        dependencies=list(dependencies.values()),
        accesses=list(accesses.values()),
        evidence_receipts=receipts,
        evidence_requests=list({r["path"]:r for r in requests}.values()),
    )
