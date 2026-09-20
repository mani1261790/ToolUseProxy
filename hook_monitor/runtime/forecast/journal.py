"""Separate opt-in queue; changing it never changes existing protection settings."""
from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .source import canonical, digest

MAX_REQUESTS = 1000
MAX_JSON_BYTES = 256 * 1024


class Journal:
    def __init__(self, path):
        self.path = Path(path)

    @classmethod
    def create(cls, path):
        path = Path(path)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        journal = cls(path)
        with journal.connect() as conn:
            conn.executescript('''
                CREATE TABLE configuration(workspace TEXT PRIMARY KEY, mode TEXT NOT NULL,
                    model TEXT NOT NULL, threshold REAL NOT NULL, generation TEXT NOT NULL);
                CREATE TABLE requests(id TEXT PRIMARY KEY, workspace TEXT NOT NULL, generation TEXT NOT NULL,
                    body TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', result TEXT, application TEXT NOT NULL DEFAULT 'waiting');
                CREATE INDEX requests_pending ON requests(state,created);
                PRAGMA user_version=1;
            ''')
        return journal

    @contextmanager
    def connect(self):
        if self.path.is_symlink():
            raise ValueError('forecast_journal_symlink')
        conn = sqlite3.connect(self.path.absolute().as_uri() + '?mode=rw', uri=True, timeout=.01)
        conn.row_factory = sqlite3.Row
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_JSON_BYTES)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def configure(self, workspace, mode, model, threshold):
        if (not isinstance(workspace, str) or not workspace or len(workspace) > 256
                or mode not in {'off', 'record', 'stop'} or not isinstance(model, str)
                or re.fullmatch('[a-f0-9]{64}', model) is None
                or type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1):
            raise ValueError('forecast_configuration_invalid')
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            generation = uuid.uuid4().hex
            conn.execute('INSERT OR REPLACE INTO configuration VALUES(?,?,?,?,?)',
                         (workspace, mode, model, threshold, generation))
            conn.execute("UPDATE requests SET state='discarded',result=NULL WHERE workspace=? AND state IN ('pending','running')", (workspace,))
        return generation

    def configuration(self, workspace):
        with self.connect() as conn:
            row = conn.execute('SELECT * FROM configuration WHERE workspace=?', (workspace,)).fetchone()
            return dict(row) if row else None

    def enqueue(self, structure, config, *, now=None):
        now = time.time() if now is None else now
        body = {'structure': structure, 'configuration': config}
        encoded = canonical(body)
        if len(encoded.encode()) > MAX_JSON_BYTES:
            raise ValueError('forecast_request_size_limit')
        request_id = digest(body)
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM configuration WHERE workspace=?', (config['workspace'],)).fetchone()
            if current is None or dict(current) != config or config['mode'] == 'off':
                raise ValueError('forecast_configuration_changed')
            if conn.execute('SELECT COUNT(*) FROM requests').fetchone()[0] >= MAX_REQUESTS:
                raise ValueError('forecast_journal_full')
            conn.execute('INSERT OR IGNORE INTO requests(id,workspace,generation,body,created,expires) VALUES(?,?,?,?,?,?)',
                         (request_id, config['workspace'], config['generation'], encoded, now, now + 2))
        return request_id

    def claim(self, model_digest):
        now = time.time()
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute("UPDATE requests SET state='expired',result=NULL WHERE state IN ('pending','running') AND expires<=?", (now,))
            row = conn.execute("SELECT r.* FROM requests r JOIN configuration c ON c.workspace=r.workspace "
                               "WHERE r.state='pending' AND c.model=? AND c.generation=r.generation "
                               "AND c.mode IN ('record','stop') ORDER BY r.created LIMIT 1", (model_digest,)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE requests SET state='running' WHERE id=?", (row['id'],))
            return dict(row)

    def finish(self, request_id, result):
        # Closed value-free response; no raw model text is accepted into the journal.
        if (type(result) is not dict or set(result) != {'status', 'probability', 'model'}
                or result['status'] not in {'predicted', 'unknown', 'unsupported', 'failed', 'stale'}
                or (result['probability'] is not None and (type(result['probability']) not in (float, int)
                    or not math.isfinite(result['probability']) or not 0 <= result['probability'] <= 1))):
            raise ValueError('forecast_result_invalid')
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT r.*,c.mode,c.generation AS current_generation,c.model FROM requests r '
                               'LEFT JOIN configuration c ON c.workspace=r.workspace WHERE r.id=?', (request_id,)).fetchone()
            if row is None or row['state'] != 'running':
                return
            valid = (row['generation'] == row['current_generation'] and row['mode'] != 'off'
                     and row['expires'] > time.time() >= row['created'] and result['model'] == row['model'])
            conn.execute('UPDATE requests SET state=?,result=? WHERE id=?',
                         ('ready' if valid else 'discarded', canonical(result) if valid else None, request_id))

    def get(self, request_id):
        with self.connect() as conn:
            row = conn.execute('SELECT * FROM requests WHERE id=?', (request_id,)).fetchone()
            return dict(row) if row else None

    def applied(self, request_id, status):
        if status not in {'record_only', 'additional_stop', 'no_stop', 'timeout', 'stale', 'unavailable'}:
            raise ValueError('forecast_application_invalid')
        with self.connect() as conn:
            conn.execute("UPDATE requests SET application=? WHERE id=? AND application='waiting'", (status, request_id))

    def consume_stop(self, request_id, config):
        """Final atomic generation/expiry/one-use check, including disable races."""
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM configuration WHERE workspace=?', (config['workspace'],)).fetchone()
            if current is None or dict(current) != config or config['mode'] != 'stop':
                return False
            now = time.time()
            changed = conn.execute("UPDATE requests SET application='additional_stop' WHERE id=? AND generation=? "
                                   "AND state='ready' AND application='waiting' AND created<=? AND expires>?",
                                   (request_id, config['generation'], now, now))
            return changed.rowcount == 1

    def history(self, workspace):
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT id,created,state,result,application, json_extract(body,'$.structure.event') AS event_id, json_extract(body,'$.structure.session') AS session_id FROM requests "
                                                  'WHERE workspace=? ORDER BY created DESC LIMIT 100', (workspace,))]
