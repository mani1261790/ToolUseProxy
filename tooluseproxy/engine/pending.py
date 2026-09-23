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
            result TEXT NOT NULL DEFAULT '{}')''')
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
    try:
        with transaction(db) as conn:
            row = conn.execute('SELECT state,lease_until FROM pending_judgments WHERE event=?',
                               (event.event_id,)).fetchone()
            if row and row[0] == 'running' and row[1] > wall():
                return pending
            conn.execute('''INSERT INTO pending_judgments(event,workspace,session,state,owner,lease_until)
                VALUES (?,?,?,?,?,?) ON CONFLICT(event) DO UPDATE SET
                state=excluded.state,owner=excluded.owner,lease_until=excluded.lease_until''',
                (event.event_id, event.workspace_id, event.session_id or '', 'running', owner, wall()+700))
        deadline = clock() + budget_seconds
        result = dict(action='unavailable', reason='judgment_budget', path=[], node_id=None)
        for attempt in range(max_attempts):
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
            if attempt + 1 < max_attempts:
                sleep(min(2 ** attempt, max(0, deadline-clock())))
        with transaction(db) as conn:
            conn.execute("UPDATE pending_judgments SET state='waiting',lease_until=0,retry_at=? WHERE event=? AND owner=?",
                         (wall()+5, event.event_id, owner))
        return dict(result, action='pending')
    except (sqlite3.Error, OSError):
        # Failure to persist a decision is never permission to execute.
        return dict(pending, reason='judgment_state_unavailable')
