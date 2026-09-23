"""Read-only projection of pinned provenance revisions, without raw ToolCall content."""
import json


def graph_snapshot(conn, event_id, workspace=None, limit=200):
    selected = conn.execute('SELECT workspace_id,session_id,tool_use_id FROM events WHERE event_id=?', (event_id,)).fetchone()
    empty = dict(nodes=[], edges=[], checks=[], truncated=False, state='not_analyzed')
    if not selected or (workspace is not None and selected[0] != workspace):
        return empty
    scope, session, call = selected
    tables = {r[0] for r in conn.execute('SELECT name FROM sqlite_master')}
    related = [r[0] for r in conn.execute(
        'SELECT event_id FROM events WHERE workspace_id=? AND session_id=? AND tool_use_id=? ORDER BY sequence_no DESC LIMIT 50',
        (scope, session, call))] if call and session else [event_id]
    marks = ','.join('?' for _ in related)
    result = dict(empty)
    if 'semantic_flow_decisions' in tables:
        result['checks'] = [dict(r) for r in conn.execute(
            f'SELECT action,reason,event_id FROM semantic_flow_decisions WHERE workspace_id=? AND event_id IN ({marks})', (scope, *related))]
    result['judgments'] = []
    if 'pending_judgments' in tables:
        result['judgments'] = [dict(r) for r in conn.execute(
            f'SELECT event,state,attempts,held FROM pending_judgments WHERE workspace=? AND event IN ({marks})', (scope, *related))]
    result['needs'] = []
    if 'flow_needs' in tables:
        result['needs'] = [dict(r) for r in conn.execute(
            f'SELECT kind FROM flow_needs WHERE scope=? AND event IN ({marks}) LIMIT 50', (scope, *related))]
    result['jobs'] = []
    if 'flow_jobs' in tables:
        result['jobs'] = [dict(r) for r in conn.execute(
            f'SELECT status,reason FROM flow_jobs WHERE scope=? AND event IN ({marks}) LIMIT 50', (scope, *related))]
    if 'graph_revisions' not in tables:
        return result
    start = None
    if 'graph_policy_checks' in tables:
        start = conn.execute(
            f'SELECT g.graph_revision FROM graph_policy_checks g JOIN graph_revisions r ON r.revision=g.graph_revision WHERE r.workspace=? AND g.event IN ({marks}) ORDER BY g.rowid DESC LIMIT 1',
            (scope, *related)).fetchone()
    if start is None:
        start = conn.execute(
            f'SELECT revision FROM graph_revisions WHERE workspace=? AND event IN ({marks}) ORDER BY rowid DESC LIMIT 1', (scope, *related)).fetchone()
    if start is None:
        return result
    protected_paths = set()
    if 'graph_policy_checks' in tables and 'graph_policies' in tables:
        policy = conn.execute('SELECT p.sources_json FROM graph_policy_checks c JOIN graph_policies p ON p.revision=c.policy_revision WHERE c.graph_revision=? ORDER BY c.rowid DESC LIMIT 1', (start[0],)).fetchone()
        if policy:
            protected_paths = {s.get('path') for s in json.loads(policy[0])}
    pending = [start[0]]
    seen, nodes, edges = set(), [], []
    while pending and len(seen) < limit:
        revision = pending.pop(0)
        if revision in seen:
            continue
        seen.add(revision)
        row = conn.execute(
            'SELECT r.node,r.event,r.session,r.verdict,e.tool_name,e.recorded_at FROM graph_revisions r JOIN events e ON e.event_id=r.event AND e.workspace_id=r.workspace WHERE r.workspace=? AND r.revision=?',
            (scope, revision)).fetchone()
        if row is None:
            result['truncated'] = True
            continue
        verdict = json.loads(row[3])
        accesses = [dict(r) for r in conn.execute('SELECT path,mode FROM graph_accesses WHERE revision=? LIMIT 64', (revision,))]
        for access in accesses:
            access['protected'] = access['mode'] == 'read' and access['path'] in protected_paths
        versions = []
        if 'flow_file_observations' in tables:
            versions = [dict(r) for r in conn.execute('SELECT path,version,mode FROM flow_file_observations WHERE scope=? AND event=? LIMIT 64', (scope, row[1]))]
        selected_output = 'graph_output_selections' in tables and conn.execute(
            'SELECT 1 FROM graph_output_selections WHERE revision=?', (revision,)).fetchone() is not None
        nodes.append(dict(provenance_scope='selected_output' if selected_output else 'operation', versions=versions, id=revision, node=row[0], event=row[1], session=row[2], tool=row[4], time=row[5], complete=verdict.get('complete') is True, accesses=accesses))
        if 'graph_revision_links' in tables:
            for parent in conn.execute('SELECT l.parent_revision FROM graph_revision_links l JOIN graph_revisions r ON r.revision=l.parent_revision WHERE l.revision=? AND r.workspace=? LIMIT 401', (revision, scope)):
                if len(edges) >= 400:
                    result['truncated'] = True
                    break
                edges.append(dict(source=parent[0], target=revision, kind='inferred'))
                if parent[0] not in seen:
                    pending.append(parent[0])
    ids = {n['id'] for n in nodes}
    result.update(nodes=nodes, edges=[e for e in edges if e['source'] in ids and e['target'] in ids], state='recorded', truncated=result['truncated'] or bool(pending))
    return result
