"""Versioned ToolCall properties and information edges, independent of policy roots."""

from __future__ import annotations

import json
import posixpath
import sqlite3
from collections import deque

from tooluseproxy.engine.graph import GraphUnavailable, digest, initialize, load_calls
from tooluseproxy.engine.judge import PROMPT_VERSION


def schema(conn):
    initialize(conn)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS graph_revisions (
            revision TEXT PRIMARY KEY, workspace TEXT NOT NULL, session TEXT NOT NULL,
            node TEXT NOT NULL, event TEXT NOT NULL, model TEXT NOT NULL, prompt TEXT NOT NULL,
            verdict TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS graph_heads (
            workspace TEXT NOT NULL, session TEXT NOT NULL, node TEXT NOT NULL,
            revision TEXT NOT NULL, PRIMARY KEY(workspace,session,node));
        CREATE TABLE IF NOT EXISTS graph_edges (
            revision TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, reason TEXT NOT NULL,
            PRIMARY KEY(revision,src,dst));
        CREATE INDEX IF NOT EXISTS graph_incoming ON graph_edges(dst,revision,src);
        CREATE INDEX IF NOT EXISTS graph_outgoing ON graph_edges(src,revision,dst);
        CREATE TABLE IF NOT EXISTS graph_accesses (
            revision TEXT NOT NULL, node TEXT NOT NULL, path TEXT NOT NULL,
            mode TEXT NOT NULL, reason TEXT NOT NULL,
            PRIMARY KEY(revision,path,mode));
        CREATE INDEX IF NOT EXISTS graph_resource ON graph_accesses(path,mode,revision,node);
        CREATE TABLE IF NOT EXISTS graph_revision_links (
            revision TEXT NOT NULL, parent_node TEXT NOT NULL, parent_revision TEXT NOT NULL,
            PRIMARY KEY(revision,parent_node));
        CREATE TABLE IF NOT EXISTS graph_policies (
            revision TEXT PRIMARY KEY, sources_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS graph_progress (
            workspace TEXT NOT NULL, session TEXT NOT NULL, event TEXT NOT NULL,
            state TEXT NOT NULL, PRIMARY KEY(workspace,session));
        CREATE TABLE IF NOT EXISTS graph_policy_checks (
            event TEXT NOT NULL, policy_revision TEXT NOT NULL, graph_revision TEXT NOT NULL,
            result TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(event,policy_revision,graph_revision));
    """)


def validate(value, candidates):
    if not isinstance(value, dict) or set(value) != {
        "externality",
        "complete",
        "reason",
        "dependencies",
        "accesses",
    }:
        raise GraphUnavailable("invalid_property_verdict")
    if (
        value["externality"] not in ("local", "external", "unknown")
        or type(value["complete"]) is not bool
    ):
        raise GraphUnavailable("invalid_property_classification")
    if not isinstance(value["reason"], str) or not 0 < len(value["reason"]) <= 4000:
        raise GraphUnavailable("invalid_property_reason")
    if not isinstance(value["dependencies"], list) or not isinstance(value["accesses"], list):
        raise GraphUnavailable("invalid_property_lists")
    seen = set()
    for edge in value["dependencies"]:
        if (
            not isinstance(edge, dict)
            or set(edge) != {"node_id", "reason"}
            or not isinstance(edge["node_id"], str)
            or edge["node_id"] not in candidates
            or edge["node_id"] in seen
            or not isinstance(edge["reason"], str)
            or not 0 < len(edge["reason"]) <= 4000
        ):
            raise GraphUnavailable("invalid_property_edge")
        seen.add(edge["node_id"])
    seen = set()
    for access in value["accesses"]:
        if not isinstance(access, dict) or set(access) != {"path", "mode", "reason"}:
            raise GraphUnavailable("invalid_access")
        path = access["path"]
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\x00" in path
            or path.startswith("/")
            or path == ".."
            or path.startswith("../")
            or posixpath.normpath(path) != path
            or access["mode"] not in ("read", "write")
            or not isinstance(access["reason"], str)
            or not 0 < len(access["reason"]) <= 4000
        ):
            raise GraphUnavailable("invalid_access")
        key = (path, access["mode"])
        if key in seen:
            raise GraphUnavailable("duplicate_access")
        seen.add(key)
    return value


def persist(conn, workspace, session, node, revision, model, verdict, parent_revisions=None):
    current = conn.execute(
        "SELECT revision FROM graph_heads WHERE workspace=? AND session=? AND node=?",
        (workspace, session, node["node_id"]),
    ).fetchone()
    if current and current[0] == revision:
        return
    conn.execute(
        "INSERT OR IGNORE INTO graph_revisions(revision,workspace,session,node,event,model,prompt,verdict) VALUES (?,?,?,?,?,?,?,?)",
        (
            revision,
            workspace,
            session,
            node["node_id"],
            node["event_id"],
            model,
            PROMPT_VERSION,
            json.dumps(verdict),
        ),
    )
    conn.executemany(
        "INSERT OR IGNORE INTO graph_edges VALUES (?,?,?,?)",
        [(revision, e["node_id"], node["node_id"], e["reason"]) for e in verdict["dependencies"]],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO graph_accesses VALUES (?,?,?,?,?)",
        [
            (revision, node["node_id"], a["path"], a["mode"], a["reason"])
            for a in verdict["accesses"]
        ],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO graph_revision_links VALUES (?,?,?)",
        [
            (revision, e["node_id"], parent_revisions[e["node_id"]])
            for e in verdict["dependencies"]
            if parent_revisions is not None
        ],
    )
    conn.execute(
        "INSERT OR REPLACE INTO graph_heads VALUES (?,?,?,?)",
        (workspace, session, node["node_id"], revision),
    )


def reach(conn, workspace, session, node, roots, limit=200_000):
    # Indexed incoming-edge lookups; no all-edge load. Keep predecessors once,
    # rather than copying complete paths at every traversal step.
    queue = deque([node])
    toward = {node: None}
    while queue:
        current = queue.popleft()
        if current in roots:
            path = [roots[current], current]
            while toward[current] is not None:
                current = toward[current]
                path.append(current)
            return path
        rows = conn.execute(
            """SELECT e.src FROM graph_heads h JOIN graph_edges e
            ON e.revision=h.revision AND e.dst=h.node
            WHERE h.workspace=? AND h.session=? AND h.node=?""",
            (workspace, session, current),
        )
        for (parent,) in rows:
            if parent not in toward:
                if len(toward) >= limit:
                    raise GraphUnavailable("graph_traversal_budget_exceeded")
                toward[parent] = current
                queue.append(parent)
    return []


def bindings(conn, workspace, session, sources):
    roots = {}
    complete = True
    for source in sources:
        selector = source.get("selector")
        if selector and (not isinstance(selector, dict) or selector.get("kind") != "whole_file"):
            complete = False
            continue
        # A policy marks the resource over the recorded history, not a claim that
        # every version contains identical bytes. Missing/ambiguous identity stays unknown.
        path = source.get("path")
        if not isinstance(path, str) or path.startswith("/") or posixpath.normpath(path) != path:
            complete = False
            continue
        rows = conn.execute(
            """SELECT a.node FROM graph_accesses a JOIN graph_heads h
            ON h.revision=a.revision AND h.node=a.node
            WHERE a.path=? AND a.mode='read' AND h.workspace=? AND h.session=?""",
            (path, workspace, session),
        )
        for (node,) in rows:
            roots[node] = source["node_id"]
    return roots, complete


def analyze_properties(
    db_path,
    workspace,
    session,
    event_id,
    sources,
    judge,
    *,
    model="codex_default",
    sources_refresh=None,
):
    with sqlite3.connect(db_path, timeout=5) as conn:
        schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO graph_progress VALUES (?,?,?,?)",
            (workspace, session, event_id, "analyzing"),
        )
        calls = load_calls(conn, workspace, session, event_id)
    if not calls:
        raise GraphUnavailable("tool_call_missing")
    prior = []
    revisions = {}
    complete = True
    current_verdict = None
    current_revision = None
    for node in calls:
        records = {"previous_calls": prior, "current_call": node}
        revision = digest([PROMPT_VERSION, model, workspace, session, records])
        with sqlite3.connect(db_path, timeout=5) as conn:
            cached = conn.execute(
                "SELECT verdict FROM graph_revisions WHERE revision=?", (revision,)
            ).fetchone()
        candidates = {n["node_id"] for n in prior if n["completed"]}
        verdict = validate(json.loads(cached[0]) if cached else judge(records), candidates)
        complete = complete and verdict["complete"]
        with sqlite3.connect(db_path, timeout=5) as conn:
            persist(conn, workspace, session, node, revision, model, verdict, revisions)
        revisions[node["node_id"]] = revision
        prior.append(
            dict(
                node,
                dependencies=verdict["dependencies"],
                accesses=verdict["accesses"],
                judgment_complete=verdict["complete"],
            )
        )
        if node["event_id"] == event_id:
            current_verdict = verdict
            current_revision = revision
            current_node = node["node_id"]
    if current_verdict is None:
        raise GraphUnavailable("current_node_missing")
    with sqlite3.connect(db_path, timeout=5) as conn:
        # Serialize the final policy snapshot and recorded decision with source
        # registration. Model requests finished before this short transaction.
        conn.execute("BEGIN IMMEDIATE")
        if sources_refresh is not None:
            sources = sources_refresh()
        policy_revision = digest(sorted(sources, key=lambda source: source["node_id"]))
        conn.execute(
            "INSERT OR IGNORE INTO graph_policies VALUES (?,?)",
            (policy_revision, json.dumps(sources)),
        )
        roots, policy_complete = bindings(conn, workspace, session, sources)
        path = reach(conn, workspace, session, current_node, roots)
        if current_verdict["externality"] == "external" and path:
            action, reason = "block", "protected_source_reachable"
        elif not complete or not policy_complete or current_verdict["externality"] == "unknown":
            action, reason = "unavailable", "property_graph_incomplete"
        else:
            action, reason = (
                "allow",
                "local_operation"
                if current_verdict["externality"] == "local"
                else "no_protected_path_observed",
            )
        result = {"node_id": current_node, "action": action, "reason": reason, "path": path}
        conn.execute(
            "INSERT OR REPLACE INTO graph_progress VALUES (?,?,?,?)",
            (workspace, session, event_id, "incomplete" if action == "unavailable" else "ready"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO graph_policy_checks(event,policy_revision,graph_revision,result) VALUES (?,?,?,?)",
            (
                event_id,
                digest(sorted(sources, key=lambda s: s["node_id"])),
                current_revision,
                json.dumps(result),
            ),
        )
    return result
