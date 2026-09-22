from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import deque
from pathlib import Path
from typing import Callable

from tooluseproxy.engine.judge import PROMPT_VERSION


class GraphUnavailable(ValueError):
    pass


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def validate_verdict(value: object, candidates: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "externality",
        "complete",
        "reason",
        "dependencies",
    }:
        raise GraphUnavailable("invalid_verdict")
    if value["externality"] not in ("local", "external", "unknown"):
        raise GraphUnavailable("invalid_externality")
    if type(value["complete"]) is not bool:
        raise GraphUnavailable("invalid_completeness")
    if not isinstance(value["reason"], str) or not 0 < len(value["reason"]) <= 4000:
        raise GraphUnavailable("invalid_reason")
    if not isinstance(value["dependencies"], list):
        raise GraphUnavailable("invalid_dependencies")
    seen = set()
    for edge in value["dependencies"]:
        if not isinstance(edge, dict) or set(edge) != {"node_id", "reason"}:
            raise GraphUnavailable("invalid_edge")
        node_id = edge["node_id"]
        if not isinstance(node_id, str) or node_id not in candidates or node_id in seen:
            raise GraphUnavailable("unknown_future_or_duplicate_dependency")
        if not isinstance(edge["reason"], str) or not 0 < len(edge["reason"]) <= 4000:
            raise GraphUnavailable("invalid_edge_reason")
        seen.add(node_id)
    return value


def protected_path(node_id: str, edges: dict[str, list[str]], roots: set[str]) -> list[str]:
    """Return an actual dependency path, without thresholds or similarity scores."""
    queue = deque([(node_id, [node_id])])
    seen = set()
    while queue:
        current, path = queue.popleft()
        if current in roots:
            return list(reversed(path))
        if current in seen:
            continue
        seen.add(current)
        queue.extend((parent, path + [parent]) for parent in edges.get(current, []))
    return []


def initialize(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS semantic_flow_nodes (
            node_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, session_id TEXT NOT NULL,
            event_id TEXT NOT NULL, request_hash TEXT NOT NULL, verdict_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS semantic_flow_edges (
            workspace_id TEXT NOT NULL, session_id TEXT NOT NULL,
            src_node_id TEXT NOT NULL, dst_node_id TEXT NOT NULL, reason TEXT NOT NULL,
            PRIMARY KEY (src_node_id, dst_node_id)
        );
        CREATE TABLE IF NOT EXISTS semantic_flow_decisions (
            event_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, session_id TEXT NOT NULL,
            node_id TEXT, action TEXT NOT NULL, reason TEXT NOT NULL,
            path_json TEXT NOT NULL, model TEXT, prompt_version TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)


def load_calls(
    conn: sqlite3.Connection,
    workspace: str,
    session: str,
    event_id: str,
    max_events: int = 500,
    max_bytes: int = 256_000,
) -> list[dict]:
    end = conn.execute("SELECT sequence_no FROM events WHERE event_id=?", (event_id,)).fetchone()
    if end is None:
        raise GraphUnavailable("event_missing")
    # Never silently drop old history or truncate contents and then report an allow.
    boundary = 0
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='recording_boundaries'").fetchone():
        row = conn.execute("SELECT after_sequence FROM recording_boundaries WHERE workspace_id=?", (workspace,)).fetchone()
        if row:
            boundary = row[0]
    rows = conn.execute(
        """SELECT event_id,phase,tool_use_id,tool_name,payload_json,workspace_root
        FROM events WHERE workspace_id=? AND session_id=? AND sequence_no<=?
        AND sequence_no>? AND phase IN ('pre_tool_use','post_tool_use') ORDER BY sequence_no LIMIT ?""",
        (workspace, session, end[0], boundary, max_events + 1),
    ).fetchall()
    if len(rows) > max_events or sum(len(row[4].encode()) for row in rows) > max_bytes:
        raise GraphUnavailable("history_budget_exceeded")
    calls: dict[str, dict] = {}
    for eid, phase, tool_id, tool_name, raw, workspace_root in rows:
        if not tool_id:
            raise GraphUnavailable("tool_use_id_missing")
        payload = json.loads(raw)
        node_id = "call:" + digest([workspace, session, tool_id])
        tool_input = payload.get("tool_input")
        if phase == "pre_tool_use":
            if node_id in calls:
                previous = calls[node_id]
                if (
                    previous["completed"]
                    or previous["input"] != tool_input
                    or previous["tool_name"] != tool_name
                    or previous["cwd"] != payload.get("cwd")
                    or previous["workspace_root"] != workspace_root
                ):
                    raise GraphUnavailable("reused_tool_use_id")
                # Redelivery can carry different runtime attestation metadata.
                previous["event_id"] = eid
                continue
            calls[node_id] = {
                "node_id": node_id,
                "event_id": eid,
                "tool_name": tool_name,
                "input": tool_input,
                "cwd": payload.get("cwd"),
                "workspace_root": workspace_root,
                "output": None,
                "completed": False,
            }
        else:
            if node_id not in calls:
                raise GraphUnavailable("pre_tool_record_missing")
            node = calls[node_id]
            if (node["input"] != tool_input or node["tool_name"] != tool_name
                    or node["cwd"] != payload.get("cwd") or node["workspace_root"] != workspace_root):
                raise GraphUnavailable("post_tool_input_mismatch")
            node.update(output=payload.get("tool_response"), completed=True, event_id=eid)
    return list(calls.values())


def analyze(
    db_path: Path,
    workspace: str,
    session: str,
    event_id: str,
    sources: list[dict],
    judge: Callable[[dict], dict],
    *,
    model: str = "codex_default",
    max_events: int = 500,
    max_bytes: int = 256_000,
) -> dict:
    with sqlite3.connect(db_path, timeout=5) as conn:
        initialize(conn)
        current = conn.execute(
            "SELECT tool_use_id FROM events WHERE event_id=? AND workspace_id=? AND session_id=?",
            (event_id, workspace, session),
        ).fetchone()
        if current is None or not current[0]:
            raise GraphUnavailable("current_tool_identity_missing")
        conn.execute(
            "INSERT OR IGNORE INTO semantic_flow_nodes "
            "(node_id,workspace_id,session_id,event_id,request_hash,verdict_json) VALUES (?,?,?,?,?,?)",
            (
                "call:" + digest([workspace, session, current[0]]),
                workspace,
                session,
                event_id,
                "",
                "{}",
            ),
        )
    with sqlite3.connect(db_path, timeout=5) as conn:
        calls = load_calls(conn, workspace, session, event_id, max_events, max_bytes)
    if not calls:
        raise GraphUnavailable("tool_call_missing")
    roots = {source["node_id"] for source in sources}
    edges: dict[str, list[str]] = {}
    with sqlite3.connect(db_path, timeout=5) as conn:
        for node in calls:
            conn.execute(
                "INSERT OR IGNORE INTO semantic_flow_nodes "
                "(node_id,workspace_id,session_id,event_id,request_hash,verdict_json) "
                "VALUES (?,?,?,?,?,?)",
                (node["node_id"], workspace, session, node["event_id"], "", "{}"),
            )
    prior = []
    complete = True
    result = None
    for node in calls:
        records = {"sources": sources, "previous_calls": prior, "current_call": node}
        request_hash = digest([PROMPT_VERSION, model, records])
        with sqlite3.connect(db_path, timeout=5) as conn:
            cached = conn.execute(
                "SELECT verdict_json FROM semantic_flow_nodes WHERE node_id=? AND request_hash=?",
                (node["node_id"], request_hash),
            ).fetchone()
        candidates = roots | {item["node_id"] for item in prior if item["completed"]}
        verdict = validate_verdict(json.loads(cached[0]) if cached else judge(records), candidates)
        edges[node["node_id"]] = [edge["node_id"] for edge in verdict["dependencies"]]
        complete = complete and verdict["complete"]
        path = protected_path(node["node_id"], edges, roots)
        if verdict["externality"] == "external" and path:
            action, reason = "block", "protected_source_reachable"
        elif not complete or verdict["externality"] == "unknown":
            action, reason = "unavailable", "semantic_judgment_incomplete"
        else:
            action, reason = (
                "allow",
                "local_operation"
                if verdict["externality"] == "local"
                else "no_protected_path_observed",
            )
        # Network calls happen outside SQLite write transactions.
        with sqlite3.connect(db_path, timeout=5) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO semantic_flow_nodes "
                "(node_id,workspace_id,session_id,event_id,request_hash,verdict_json) "
                "VALUES (?,?,?,?,?,?)",
                (
                    node["node_id"],
                    workspace,
                    session,
                    node["event_id"],
                    request_hash,
                    json.dumps(verdict),
                ),
            )
            conn.execute("DELETE FROM semantic_flow_edges WHERE dst_node_id=?", (node["node_id"],))
            conn.executemany(
                "INSERT INTO semantic_flow_edges VALUES (?,?,?,?,?)",
                [
                    (workspace, session, edge["node_id"], node["node_id"], edge["reason"])
                    for edge in verdict["dependencies"]
                ],
            )
        prior.append(
            dict(node, dependencies=verdict["dependencies"], judgment_complete=verdict["complete"])
        )
        if node["event_id"] == event_id:
            result = {"node_id": node["node_id"], "action": action, "reason": reason, "path": path}
    if result is None:
        raise GraphUnavailable("current_node_missing")
    return result
