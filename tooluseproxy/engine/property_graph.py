"""Versioned ToolCall properties and information edges, independent of policy roots."""

from __future__ import annotations

import json
import posixpath
import sqlite3
import time
from collections import deque
from contextlib import closing

from tooluseproxy.engine.graph import GraphUnavailable, digest, initialize, load_calls
from tooluseproxy.engine.judge import PROMPT_VERSION
from tooluseproxy.engine.requirements import reusable


def schema(conn):
    initialize(conn)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS graph_revisions (
            revision TEXT PRIMARY KEY, workspace TEXT NOT NULL, session TEXT NOT NULL,
            node TEXT NOT NULL, event TEXT NOT NULL, model TEXT NOT NULL, prompt TEXT NOT NULL,
            verdict TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS graph_completed_reviews (
            request TEXT PRIMARY KEY, revision TEXT NOT NULL);
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
        CREATE TABLE IF NOT EXISTS graph_output_selections (
            revision TEXT PRIMARY KEY, node TEXT NOT NULL, selection_json TEXT NOT NULL,
            observation_hash TEXT NOT NULL);
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
    if not isinstance(value, dict) or set(value) - {"evidence_requests", "evidence_receipts"} != {
        "externality",
        "complete",
        "reason",
        "dependencies",
        "accesses",
    }:
        raise GraphUnavailable("invalid_property_verdict")
    if value["externality"] not in ("local", "external") or type(value["complete"]) is not bool:
        raise GraphUnavailable("invalid_property_classification")
    if not isinstance(value["reason"], str) or not 0 < len(value["reason"]) <= 4000:
        raise GraphUnavailable("invalid_property_reason")
    if not isinstance(value["dependencies"], list) or not isinstance(value["accesses"], list):
        raise GraphUnavailable("invalid_property_lists")
    dependencies = {}
    for edge in value["dependencies"]:
        if (
            not isinstance(edge, dict)
            or set(edge) - {"selection"} != {"node_id", "reason"}
            or not isinstance(edge["node_id"], str)
            or edge["node_id"] not in candidates
            or not isinstance(edge["reason"], str)
            or not 0 < len(edge["reason"]) <= 4000
        ):
            raise GraphUnavailable("invalid_property_edge")
        selection = edge.get("selection")
        if selection is not None and (
            not isinstance(selection, dict) or set(selection) != {"text"}
            or not isinstance(selection["text"], str) or not 0 < len(selection["text"]) <= 128_000
        ):
            raise GraphUnavailable("invalid_output_selection")
        old = dependencies.get(edge["node_id"])
        # Multiple fields from one producer form one graph edge. Preserve all
        # contributions by widening conflicting selections, never dropping an
        # edge or paying for another model request to fix a list duplicate.
        dependencies[edge["node_id"]] = (
            dict(edge, selection=None)
            if old is not None and old.get("selection") != selection else edge
        )
    accesses = {}
    for access in value["accesses"]:
        if not isinstance(access, dict) or set(access) != {"path", "mode", "reason"}:
            raise GraphUnavailable("invalid_access")
        path = access["path"]
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\x00" in path
            or path == ".."
            or path.startswith("../")
            or posixpath.normpath(path) != path
            or access["mode"] not in ("read", "write")
            or not isinstance(access["reason"], str)
            or not 0 < len(access["reason"]) <= 4000
        ):
            raise GraphUnavailable("invalid_access")
        key = (path, access["mode"])
        accesses[key] = access
    requests = value.get("evidence_requests", [])
    if not isinstance(requests, list) or len(requests) > 8:
        raise GraphUnavailable("invalid_evidence_requests")
    for request in requests:
        if (not isinstance(request, dict) or set(request) != {"path", "reason"}
            or not all(isinstance(request[k], str) and 0 < len(request[k]) <= 4096 for k in request)):
            raise GraphUnavailable("invalid_evidence_request")
    if value["complete"] and requests:
        raise GraphUnavailable("completed_with_evidence_requests")
    return dict(value, dependencies=list(dependencies.values()), accesses=list(accesses.values()))


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


def revision_parents(conn, workspace, node, revision):
    rows = conn.execute(
        """SELECT e.src,l.parent_revision FROM graph_edges e
        LEFT JOIN graph_revision_links l ON l.revision=e.revision AND l.parent_node=e.src
        WHERE e.revision=? AND e.dst=?""",
        (revision, node),
    ).fetchall()
    result = []
    for parent, parent_revision in rows:
        if parent_revision is None:
            # Compatibility for graph-only fixtures/benchmarks, not persisted judgments.
            if conn.execute(
                "SELECT 1 FROM graph_revisions WHERE revision=?", (revision,)
            ).fetchone():
                raise GraphUnavailable("dependency_revision_missing")
            row = conn.execute(
                "SELECT revision FROM graph_heads WHERE workspace=? AND node=?", (workspace, parent)
            ).fetchone()
            parent_revision = row[0] if row else None
        if parent_revision is None:
            raise GraphUnavailable("dependency_node_missing")
        result.append((parent, parent_revision))
    return result


def reach(conn, workspace, session, node, roots, limit=200_000):
    head = conn.execute(
        "SELECT revision FROM graph_heads WHERE workspace=? AND session=? AND node=?",
        (workspace, session, node),
    ).fetchone()
    if not head:
        return []
    start = (node, head[0])
    queue, toward = deque([start]), {start: None}
    while queue:
        current = queue.popleft()
        source = roots.get(current, roots.get(current[0]))
        if source:
            path = [source, current[0]]
            while toward[current] is not None:
                current = toward[current]
                path.append(current[0])
            return path
        for parent in revision_parents(conn, workspace, *current):
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
            """SELECT a.node,a.revision FROM graph_accesses a JOIN graph_revisions r
            ON r.revision=a.revision AND r.node=a.node
            WHERE a.path=? AND a.mode='read' AND r.workspace=?""",
            (path, workspace),
        )
        for node, revision in rows:
            roots[(node, revision)] = source["node_id"]
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
    current_evidence=None,
    require_external=False,
    _visiting=None,
):
    with sqlite3.connect(db_path, timeout=5) as conn:
        schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO graph_progress VALUES (?,?,?,?)",
            (workspace, session, event_id, "analyzing"),
        )
    from tooluseproxy.engine.lineage import attach_witnesses, link_producers

    visiting = set() if _visiting is None else _visiting
    if event_id in visiting or len(visiting) >= 64:
        raise GraphUnavailable("resource_lineage_expansion_budget")
    visiting.add(event_id)
    with sqlite3.connect(db_path, timeout=5) as conn:
        calls = load_calls(conn, workspace, session, event_id, 50_000, 64_000_000)
    if not calls:
        raise GraphUnavailable("tool_call_missing")
    current_verdict = None
    evidence_context = {}
    with closing(sqlite3.connect(db_path, timeout=5)) as conn:
        prefixes = []
        prefix = digest(["demand-history-v1", PROMPT_VERSION, model, workspace, session])
        for node in calls:
            attach_witnesses(conn, workspace, node)
            if node["event_id"] == event_id and current_evidence is not None:
                node["payload_observations"] = current_evidence
            prefixes.append(prefix)
            prefix = digest([prefix, node])
        by_id = {n["node_id"]: i for i, n in enumerate(calls)}
        assessed = {}

        def assess(index, selection=None, depth=0):
            if depth >= 128 or len(assessed) > 50_000:
                raise GraphUnavailable("output_provenance_expansion_budget")
            producer = calls[index]
            key = (index, digest(selection))
            if key in assessed:
                return assessed[key]
            focused = dict(producer)
            if selection is not None:
                observed = producer["output"] if isinstance(producer["output"], str) else json.dumps(producer["output"], ensure_ascii=False, sort_keys=True)
                if not producer["completed"] or observed.count(selection["text"]) != 1:
                    raise GraphUnavailable("output_selection_missing_or_ambiguous")
                focused["required_output"] = dict(selection, observation_hash=digest(producer["output"]))
            records = {"previous_calls": calls[:index], "current_call": focused}
            request = digest(["demand-review-v1", prefixes[index], focused])
            cached = conn.execute("SELECT r.verdict FROM graph_completed_reviews c JOIN graph_revisions r ON r.revision=c.revision WHERE c.request=?", (request,)).fetchone()
            if cached and not reusable(json.loads(cached[0]), producer):
                cached = None
            candidates = {n["node_id"] for n in calls[:index] if n["completed"]}
            from tooluseproxy.engine.contracts import provenance_contract
            mechanical = provenance_contract(focused)
            if mechanical is not None:
                verdict = validate(mechanical, candidates)
            elif cached:
                verdict = validate(json.loads(cached[0]), candidates)
            else:
                from tooluseproxy.engine.review import review
                verdict = review(db_path, request, records, judge, validate, evidence_context=evidence_context)
            # A transmitted value selected from a controller-loaded observation
            # has a mandatory producer edge. A model cannot omit that provenance.
            observed_edges = {}
            for part in producer.get('payload_observations', []):
                parent = part.get('observation', {}).get('source_node_id')
                if parent is None:
                    continue
                if parent not in candidates:
                    raise GraphUnavailable('observed_transmission_parent_missing')
                original = calls[by_id[parent]]['output']
                original = original if isinstance(original, str) else json.dumps(original, ensure_ascii=False, sort_keys=True)
                content = part.get('content', '')
                output_selection = ({'text': content} if part.get('encoding') == 'utf-8'
                             and content and original.count(content) == 1 else None)
                old = observed_edges.get(parent)
                if old is not None and old['selection'] != output_selection:
                    output_selection = None
                observed_edges[parent] = dict(node_id=parent, selection=output_selection,
                                              reason='controller-resolved transmitted output')
            if observed_edges:
                dependencies = {edge['node_id']: edge for edge in verdict['dependencies']}
                for parent, edge in observed_edges.items():
                    old = dependencies.get(parent)
                    if old is not None and old.get('selection') != edge['selection']:
                        edge = dict(edge, selection=None)
                    dependencies[parent] = edge
                verdict = dict(verdict, dependencies=list(dependencies.values()))
            # Relative and absolute aliases must name the same policy resource.
            from tooluseproxy.engine.requirements import resource_identity
            verdict = dict(verdict, accesses=[dict(a, path=resource_identity(a["path"], producer["workspace_root"])) for a in verdict["accesses"]])
            links = {}
            for edge in verdict["dependencies"]:
                parent_index = by_id[edge["node_id"]]
                if parent_index >= index:
                    raise GraphUnavailable("future_output_dependency")
                links[edge["node_id"]] = assess(parent_index, edge.get("selection"), depth+1)[0]
            # A same-session file producer may be needed even without a direct
            # ToolCall edge: demand-driven analysis must materialize that revision.
            from tooluseproxy.engine.lineage import matching_producers
            reads = {a["path"] for a in verdict["accesses"] if a["mode"] == "read"}
            origins = matching_producers(conn, workspace, producer["event_id"])
            for origin_event, origin_session, path, _ in origins:
                if path not in reads:
                    continue
                if origin_session == session:
                    origin_index = next((i for i,n in enumerate(calls[:index]) if n["event_id"] == origin_event), None)
                    if origin_index is not None:
                        assess(origin_index, None, depth+1)
                else:
                    # Materialize only generations actually consumed by this
                    # value, not every earlier read in the entire session.
                    # The producer recursively checks its own current evidence
                    # and caches; policy roots never decide which edges to keep.
                    analyze_properties(
                        db_path, workspace, origin_session, origin_event,
                        sources, judge, model=model, sources_refresh=sources_refresh,
                        _visiting=visiting,
                    )
            resource_links = []
            for origin_event, _, path, _ in origins:
                if path in reads:
                    parent = conn.execute("SELECT h.node,h.revision FROM graph_heads h JOIN graph_revisions r ON r.revision=h.revision JOIN graph_accesses a ON a.revision=r.revision WHERE h.workspace=? AND r.event=? AND a.path=? AND a.mode='write'", (workspace, origin_event, path)).fetchone()
                    if parent:
                        resource_links.append(parent)
            revision = digest([request, verdict, links, resource_links])
            old_head = conn.execute("SELECT revision FROM graph_heads WHERE workspace=? AND session=? AND node=?", (workspace, session, producer["node_id"])).fetchone()
            with conn:
                persist(conn, workspace, session, producer, revision, model, verdict, links)
                link_producers(conn, workspace, producer, revision, verdict)
                if selection is not None:
                    conn.execute("INSERT OR IGNORE INTO graph_output_selections VALUES (?,?,?,?)", (revision, producer["node_id"], json.dumps(selection), digest(producer["output"])))
                    # Keep scoped reviews out of the whole-operation head/cache.
                    if old_head:
                        conn.execute("UPDATE graph_heads SET revision=? WHERE workspace=? AND session=? AND node=?", (old_head[0], workspace, session, producer["node_id"]))
                    else:
                        conn.execute("DELETE FROM graph_heads WHERE workspace=? AND session=? AND node=?", (workspace, session, producer["node_id"]))
                if verdict["complete"]:
                    conn.execute("INSERT OR REPLACE INTO graph_completed_reviews VALUES (?,?)", (request, revision))
            assessed[key] = (revision, verdict)
            return revision, verdict

        for index, node in enumerate(calls):
            if node["event_id"] == event_id:
                current_revision, current_verdict = assess(index)
                current_node = node["node_id"]
                break
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
        traversal_started = time.monotonic_ns()
        complete = dependency_complete(conn, workspace, current_node)
        roots, policy_complete = bindings(conn, workspace, session, sources)
        path = reach(conn, workspace, session, current_node, roots)
        if current_verdict["externality"] == "local" and not require_external:
            # Local work need not wait for provenance that only a later send needs.
            # Keep incomplete verdicts intact so that send still requires inspection.
            action, reason = "allow", "local_operation"
        elif path:
            action, reason = "block", "protected_source_reachable"
        elif not complete or not policy_complete:
            action, reason = "unavailable", "property_graph_incomplete"
        else:
            action, reason = "allow", "no_protected_path_observed"
        result = {"node_id": current_node, "action": action, "reason": reason, "path": path,
                  "reachability_ms": (time.monotonic_ns() - traversal_started) / 1_000_000}
        if action == "unavailable":
            result["retryable"] = False
            result["evidence_needs"] = unresolved_dependencies(conn, workspace, current_node)
        conn.execute(
            "INSERT OR REPLACE INTO graph_progress VALUES (?,?,?,?)",
            (
                workspace,
                session,
                event_id,
                "incomplete" if not complete or not policy_complete else "ready",
            ),
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
    visiting.remove(event_id)
    return result


def dependency_complete(conn, workspace, node):
    head = conn.execute(
        "SELECT revision FROM graph_heads WHERE workspace=? AND node=?", (workspace, node)
    ).fetchone()
    if not head:
        return False
    pending, seen = [(node, head[0])], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if len(seen) > 200_000:
            raise GraphUnavailable("graph_completeness_budget")
        row = conn.execute(
            "SELECT verdict FROM graph_revisions WHERE workspace=? AND node=? AND revision=?",
            (workspace, *current),
        ).fetchone()
        if not row or not json.loads(row[0])["complete"]:
            return False
        pending.extend(revision_parents(conn, workspace, *current))
    return True


def unresolved_dependencies(conn, workspace, node):
    head = conn.execute("SELECT revision FROM graph_heads WHERE workspace=? AND node=?", (workspace, node)).fetchone()
    pending = [(node, head[0])] if head else []
    seen, needs = set(), []
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if len(seen) >= 200_000:
            raise GraphUnavailable("graph_traversal_budget_exceeded")
        seen.add(current)
        row = conn.execute("SELECT verdict FROM graph_revisions WHERE workspace=? AND node=? AND revision=?", (workspace, *current)).fetchone()
        if row:
            value = json.loads(row[0])
            if not value["complete"]:
                needs.append(dict(node_id=current[0], revision=current[1], reason=value["reason"],
                                  requests=value.get("evidence_requests", []), receipts=value.get("evidence_receipts", [])))
        pending.extend(revision_parents(conn, workspace, *current))
    return needs
