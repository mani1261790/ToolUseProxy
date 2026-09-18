"""Dedicated bounded forecast journal; never opens or migrates the Hook event DB."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, identifier
from .contracts import Request, parse_request


APPLICATION_ID = 0x46524344
MAX_RECORDS = 1000
MAX_RESULT_BYTES = 256 * 1024
TERMINAL = frozenset({'recorded', 'expired', 'input_version_changed', 'model_version_changed',
                      'different_workspace', 'different_session', 'clock_reversed', 'project_generation_changed',
                      'disabled', 'model_missing', 'model_invalid', 'timeout', 'worker_failed',
                      'out_of_domain', 'interrupted', 'input_database_failure', 'input_unavailable'})


def clock_value(now):
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        raise ForecastDataError('invalid_recording_clock')


class Journal:
    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def create(cls, path: Path):
        # Exclusive creation prevents accidental adoption of events.db or another
        # user's SQLite file. No parent directory is created implicitly.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with sqlite3.connect(path) as conn:
            conn.executescript(f'''
                PRAGMA application_id={APPLICATION_ID};
                PRAGMA user_version=1;
                CREATE TABLE projects(workspace TEXT PRIMARY KEY, enabled INTEGER NOT NULL,
                                      generation INTEGER NOT NULL);
                CREATE TABLE records(request_id TEXT PRIMARY KEY, workspace TEXT NOT NULL,
                    generation INTEGER NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    request_json TEXT NOT NULL, status TEXT NOT NULL, token TEXT, deadline REAL,
                    result_json TEXT);
                CREATE INDEX pending_records ON records(workspace, status, created);
            ''')
        return cls(path)

    @contextmanager
    def connection(self, *, write=False):
        if self.path.is_symlink() or not self.path.is_file():
            raise ForecastDataError('recording_database_unavailable')
        conn = None
        try:
            uri = self.path.resolve().as_uri() + ('?mode=rw' if write else '?mode=ro')
            conn = sqlite3.connect(uri, uri=True, timeout=.1)
            conn.row_factory = sqlite3.Row
            if (conn.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or conn.execute('PRAGMA user_version').fetchone()[0] != 1):
                raise ForecastDataError('recording_database_identity_mismatch')
            if write:
                conn.execute('PRAGMA max_page_count=4096')
                conn.execute('BEGIN IMMEDIATE')
            else:
                conn.execute('PRAGMA query_only=ON')
            yield conn
            if write:
                conn.commit()
        except sqlite3.Error:
            if conn is not None:
                conn.rollback()
            raise ForecastDataError('recording_database_failure') from None
        finally:
            if conn is not None:
                conn.close()

    def configure(self, workspace: str, *, enabled: bool):
        identifier(workspace)
        if type(enabled) is not bool:
            raise ForecastDataError('invalid_recording_configuration')
        with self.connection(write=True) as conn:
            previous = conn.execute('SELECT * FROM projects WHERE workspace=?', (workspace,)).fetchone()
            generation = previous['generation'] if previous else 0
            if previous is None or bool(previous['enabled']) != enabled:
                generation += 1
            conn.execute('INSERT OR REPLACE INTO projects VALUES(?,?,?)', (workspace, int(enabled), generation))
            if not enabled:
                conn.execute("UPDATE records SET status='disabled',token=NULL,deadline=NULL WHERE workspace=? AND status IN ('pending','running')", (workspace,))
            return generation

    def configured(self, workspace):
        identifier(workspace)
        if not self.path.exists():
            return None
        with self.connection() as conn:
            row = conn.execute('SELECT * FROM projects WHERE workspace=?', (workspace,)).fetchone()
            return row['generation'] if row and row['enabled'] else None

    def enqueue(self, request: Request, *, current, now):
        clock_value(now)
        # No write transaction or record for an unconfigured workspace.
        if self.configured(request.binding.workspace_id) is None:
            return 'unconfigured'
        reason = request.validity(current, request.model_digest, now)
        if reason != 'current':
            return reason
        with self.connection(write=True) as conn:
            config = conn.execute('SELECT * FROM projects WHERE workspace=?', (request.binding.workspace_id,)).fetchone()
            if not config or not config['enabled']:
                return 'unconfigured'
            if config['generation'] != request.binding.project_generation:
                return 'project_generation_changed'
            old = conn.execute('SELECT status FROM records WHERE request_id=?', (request.request_id,)).fetchone()
            if old:
                return old['status']
            if conn.execute('SELECT count(*) FROM records').fetchone()[0] >= MAX_RECORDS:
                return 'recording_capacity_exceeded'
            conn.execute('INSERT INTO records VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)',
                         (request.request_id, request.binding.workspace_id, config['generation'], request.created_at,
                          request.created_at + request.ttl_seconds, canonical(asdict(request)), 'pending'))
            return 'pending'

    def claim(self, workspace, *, now, lease_seconds=5):
        clock_value(now)
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 10:
            raise ForecastDataError('invalid_recording_lease')
        if self.configured(workspace) is None:
            return None
        with self.connection(write=True) as conn:
            config = conn.execute('SELECT * FROM projects WHERE workspace=?', (workspace,)).fetchone()
            if not config or not config['enabled']:
                return None
            conn.execute("UPDATE records SET status='expired' WHERE workspace=? AND status='pending' AND expires<=?", (workspace, now))
            row = conn.execute("SELECT * FROM records WHERE workspace=? AND generation=? AND status='pending' ORDER BY created,request_id LIMIT 1",
                               (workspace, config['generation'])).fetchone()
            if row is None:
                return None
            request = parse_request(json.loads(row['request_json']))
            if request.request_id != row['request_id'] or request.binding.workspace_id != workspace:
                raise ForecastDataError('recording_request_integrity_failure')
            token = secrets.token_hex(16)
            conn.execute("UPDATE records SET status='running',token=?,deadline=? WHERE request_id=?",
                         (token, min(now + lease_seconds, row['expires']), row['request_id']))
            return request, token

    def finish(self, request, token, *, status, result=None, now):
        clock_value(now)
        if status not in TERMINAL or (status == 'recorded') != (result is not None):
            raise ForecastDataError('invalid_recording_result_status')
        encoded = canonical(result) if result is not None else None
        if encoded is not None and len(encoded.encode()) > MAX_RESULT_BYTES:
            raise ForecastDataError('recording_result_size_limit')
        with self.connection(write=True) as conn:
            row = conn.execute('SELECT * FROM records WHERE request_id=?', (request.request_id,)).fetchone()
            config = conn.execute('SELECT * FROM projects WHERE workspace=?', (request.binding.workspace_id,)).fetchone()
            if (row is None or row['status'] != 'running' or row['token'] != token
                    or not config or not config['enabled'] or config['generation'] != request.binding.project_generation):
                return 'discarded'
            if now < row['created']:
                status, encoded = 'clock_reversed', None
            elif now >= row['expires']:
                status, encoded = 'expired', None
            elif now >= row['deadline']:
                status, encoded = 'timeout', None
            conn.execute('UPDATE records SET status=?,result_json=?,token=NULL,deadline=NULL WHERE request_id=?',
                         (status, encoded, request.request_id))
            return status

    def recover(self, workspace, *, now):
        clock_value(now)
        if self.configured(workspace) is None:
            return 0
        with self.connection(write=True) as conn:
            cursor = conn.execute("UPDATE records SET status='interrupted',token=NULL,deadline=NULL WHERE workspace=? AND status='running' AND deadline<=?", (workspace, now))
            return cursor.rowcount

    def history(self, workspace, *, limit=20):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ForecastDataError('invalid_recording_history_limit')
        if self.configured(workspace) is None:
            return ()
        with self.connection() as conn:
            rows = conn.execute('SELECT request_id,status,created,expires,result_json FROM records WHERE workspace=? ORDER BY created DESC,request_id LIMIT ?', (workspace, limit)).fetchall()
            # Historical records are labelled as history, not current safety results.
            return tuple({'request_id': row['request_id'], 'status': row['status'], 'created': row['created'],
                          'expires': row['expires'], 'historical_only': True,
                          'result': json.loads(row['result_json']) if row['result_json'] else None} for row in rows)
