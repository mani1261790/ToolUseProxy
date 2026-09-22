"""Positive-only shortcut with a witnessed generation and reusable ancestry.
No candidate miss or partial inspection can produce an allow here.
"""

import json
import sqlite3

from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.judge import PROMPT_VERSION
from tooluseproxy.engine.lineage import attach_witnesses, matching_producers
from tooluseproxy.engine.property_graph import bindings, persist, reach, revision_parents, schema


def reusable(conn, workspace, node, revision, model):
    pending, seen = [(node, revision)], set()
    while pending:
        item = pending.pop()
        if item in seen:
            continue
        seen.add(item)
        if len(seen) > 200_000:
            return False
        row = conn.execute(
            "SELECT model,prompt,verdict FROM graph_revisions WHERE workspace=? AND node=? AND revision=?",
            (workspace, *item),
        ).fetchone()
        if (
            not row
            or row[0] != model
            or row[1] != PROMPT_VERSION
            or not json.loads(row[2])["complete"]
        ):
            return False
        pending.extend(revision_parents(conn, workspace, *item))
    return True


def known_protected_generation(store, event, resolver, resolution, sources, model):
    if not resolver.unchanged(resolution):
        return None
    selected = {
        part.version.resource.locator: part.version.identity
        for part in resolution.parts
        if part.version.resource.kind == "file"
    }
    if not selected:
        return None
    with sqlite3.connect(store.db_path, timeout=5) as conn:
        schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        roots, _ = bindings(conn, event.workspace_id, event.session_id, sources)
        for producer, session, path, version in matching_producers(
            conn, event.workspace_id, event.event_id
        ):
            if selected.get(path) != version:
                continue
            parent = conn.execute(
                """SELECT h.node,h.revision FROM graph_heads h JOIN graph_revisions r ON r.revision=h.revision
                JOIN graph_accesses a ON a.revision=h.revision WHERE h.workspace=? AND r.event=? AND a.path=? AND a.mode='write' """,
                (event.workspace_id, producer, path),
            ).fetchone()
            if not parent or not reusable(conn, event.workspace_id, *parent, model):
                continue
            ancestry = reach(conn, event.workspace_id, session, parent[0], roots)
            if not ancestry:
                continue
            node = dict(
                node_id="call:" + digest([event.workspace_id, event.session_id, event.tool_use_id]),
                event_id=event.event_id,
                tool_name=event.raw_payload.get("tool_name"),
                input=event.raw_payload.get("tool_input"),
                output=None,
                completed=False,
            )
            attach_witnesses(conn, event.workspace_id, node)
            verdict = dict(
                externality="external",
                complete=False,
                reason="positive witnessed outbound generation; other dependencies not analyzed",
                dependencies=[
                    dict(node_id=parent[0], reason="witnessed outbound resource generation")
                ],
                accesses=[dict(path=path, mode="read", reason="resolved outbound resource")],
            )
            revision = digest(
                ["positive-generation-v1", model, PROMPT_VERSION, node, parent, version]
            )
            persist(
                conn,
                event.workspace_id,
                event.session_id,
                node,
                revision,
                model,
                verdict,
                {parent[0]: parent[1]},
            )
            result = dict(
                node_id=node["node_id"],
                action="block",
                reason="protected_source_reachable",
                path=ancestry + [node["node_id"]],
            )
            policy = digest(sorted(sources, key=lambda source: source["node_id"]))
            conn.execute(
                "INSERT OR IGNORE INTO graph_policies VALUES (?,?)", (policy, json.dumps(sources))
            )
            conn.execute(
                "INSERT OR IGNORE INTO graph_policy_checks(event,policy_revision,graph_revision,result) VALUES (?,?,?,?)",
                (event.event_id, policy, revision, json.dumps(result)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO graph_progress VALUES (?,?,?,?)",
                (event.workspace_id, event.session_id, event.event_id, "positive_generation"),
            )
            return result
    return None
