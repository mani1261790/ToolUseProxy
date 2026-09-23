"""Persist judgment attempts; never execute a ToolCall from a retry worker."""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager


@contextmanager
def transaction(db):
    conn = sqlite3.connect(db, timeout=5)
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('''CREATE TABLE IF NOT EXISTS pending_judgments (
            event TEXT PRIMARY KEY, workspace TEXT NOT NULL, session TEXT NOT NULL,
            state TEXT NOT NULL, owner TEXT, lease_until REAL NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0,
            result TEXT NOT NULL DEFAULT '{}', held INTEGER NOT NULL DEFAULT 0)''')
        if 'held' not in {r[1] for r in conn.execute('PRAGMA table_info(pending_judgments)')}:
            conn.execute('ALTER TABLE pending_judgments ADD COLUMN held INTEGER NOT NULL DEFAULT 0')
        conn.execute('''CREATE TABLE IF NOT EXISTS judgment_attempts (
            event TEXT NOT NULL, attempt INTEGER NOT NULL, result TEXT NOT NULL,
            PRIMARY KEY(event,attempt))''')
        yield conn
        conn.commit()
    finally:
        conn.close()


def decide(db, event, operation, *, max_attempts=3, budget_seconds=480,
           sleep=time.sleep, clock=time.monotonic, wall=time.time):
    """Retry incomplete analysis within a host call; retain work beyond that call.

    Completed judgments are not reused here: every new delivery revalidates the
    current resources and policy. Lower layers reuse only their scoped evidence.
    """
    owner = secrets.token_hex(16)
    pending = dict(action='pending', reason='judgment_in_progress', path=[], node_id=None)
    deadline = clock() + budget_seconds
    try:
        while True:
            with transaction(db) as conn:
                row = conn.execute('SELECT state,lease_until FROM pending_judgments WHERE event=?',
                                   (event.event_id,)).fetchone()
                busy = row and row[0] == 'running' and row[1] > wall()
                if not busy:
                    conn.execute('''INSERT INTO pending_judgments(event,workspace,session,state,owner,lease_until)
                        VALUES (?,?,?,?,?,?) ON CONFLICT(event) DO UPDATE SET
                        state=excluded.state,owner=excluded.owner,lease_until=excluded.lease_until''',
                        (event.event_id, event.workspace_id, event.session_id or '', 'running', owner, wall()+700))
                    break
            # Another live delivery is evidence of work in progress, not a
            # missing judgment. Wait outside the transaction, then revalidate
            # current resources/policy using its completed lower-level caches.
            if clock() >= deadline:
                return dict(pending, reason='judgment_wait_budget')
            sleep(min(0.1, max(0, deadline-clock())))
        result = dict(action='unavailable', reason='judgment_budget', path=[], node_id=None)
        count = 0
        attempt = 0
        while True:
            if clock() >= deadline:
                break
            try:
                result = operation(deadline)
            except Exception:
                result = dict(action='unavailable', reason='judgment_attempt_failed', path=[], node_id=None)
            if not isinstance(result, dict) or result.get('action') not in ('allow', 'block', 'unavailable'):
                result = dict(action='unavailable', reason='judgment_invalid_result', path=[], node_id=None)
            complete = result['action'] in ('allow', 'block')
            with transaction(db) as conn:
                row = conn.execute('SELECT attempts FROM pending_judgments WHERE event=? AND owner=?',
                                   (event.event_id, owner)).fetchone()
                if row is None:
                    return dict(pending, reason='judgment_ownership_changed')
                count = row[0] + 1
                conn.execute('INSERT INTO judgment_attempts VALUES (?,?,?)',
                             (event.event_id, count, json.dumps(result)))
                conn.execute('UPDATE pending_judgments SET attempts=?,result=?,state=? WHERE event=? AND owner=?',
                             (count, json.dumps(result), 'complete' if complete else 'running', event.event_id, owner))
            if complete:
                return result
            if result.get('retryable') is False:
                break
            attempt += 1
            # A fast transport failure must not spend an arbitrary three-strike
            # allowance while most of the live Hook budget remains. Evidence or
            # programming failures retain their bounded attempt policy.
            if result.get('retry_scope') != 'provider' and attempt >= max_attempts:
                break
            sleep(min(2 ** min(attempt - 1, 5), max(0, deadline-clock())))
        with transaction(db) as conn:
            state = 'needs_evidence' if result.get('retryable') is False else 'waiting'
            conn.execute("UPDATE pending_judgments SET state=?,held=1,lease_until=0,retry_at=? WHERE event=? AND owner=?",
                         (state, wall()+min(300, 5 * 2 ** min(count // 3, 6)), event.event_id, owner))
        return dict(result, action='pending')
    except (sqlite3.Error, OSError):
        # Failure to persist a decision is never permission to execute.
        return dict(pending, reason='judgment_state_unavailable')


def status(db, workspace):
    if not db.is_file():
        return {}
    with sqlite3.connect(db) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='pending_judgments'").fetchone():
            return {}
        return dict(conn.execute('SELECT state,COUNT(*) FROM pending_judgments WHERE workspace=? GROUP BY state',
                                 (workspace,)))


def resume(db, workspace, *, max_jobs=4, provider=None, now=None, operation=None):
    """Reassess saved PreToolUse observations, without dispatching their tools.

    The host must request execution again; a completed background review is not
    an execution capability. That new request rechecks current policy/resources.
    """
    from tooluseproxy.engine.journal import Event
    from tooluseproxy.engine.runtime import configuration, _process_once
    from tooluseproxy.integrations.activation import enabled_workspace_root
    from tooluseproxy.integrations.authority import registered_workspace_authority_lease

    now = time.time() if now is None else now
    if not status(db, workspace):
        return 0
    with sqlite3.connect(db) as conn:
        rows = conn.execute('''SELECT p.event FROM pending_judgments p
            WHERE p.workspace=? AND ((p.state='waiting' AND p.retry_at<=?)
            OR (p.state='running' AND p.lease_until<=?)) ORDER BY p.retry_at LIMIT ?''',
            (workspace, now, now, max_jobs)).fetchall()
    completed = 0
    for (event_id,) in rows:
        # Respect the same administrator boundary used by live Hooks. Unsetup
        # waits for these bounded reads/judgments; no setting is re-enabled here.
        with sqlite3.connect(db) as conn:
            with registered_workspace_authority_lease(db, conn, workspace) as authority:
                if authority is not None and authority.phase != 'active':
                    continue
                config = configuration(db, workspace)
                if not config:
                    continue
                row = conn.execute('''SELECT phase,workspace_root,session_id,tool_use_id,payload_json
                    FROM events WHERE event_id=? AND workspace_id=?''', (event_id, workspace)).fetchone()
                if not row or row[0] != 'pre_tool_use':
                    continue
                phase, root, session, tool, raw = row
                if enabled_workspace_root(db, root) != root:
                    continue
                event = Event(event_id, phase, workspace, root, session, tool, json.loads(raw))
                from tooluseproxy.engine.journal import Journal
                def evaluate(deadline):
                    if operation is not None:
                        return operation(event, deadline)
                    return _process_once(Journal(db), event, judge=provider, deadline=deadline, background=True)
                result = decide(db, event, evaluate)
                completed += result['action'] in ('allow', 'block')
    return completed
