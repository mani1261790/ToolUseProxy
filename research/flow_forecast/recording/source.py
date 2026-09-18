"""Bounded, read-only versions of recorded inputs, never a synthetic Prefix.

This adapter hashes local rows without returning their contents. A snapshot is
not evidence that a model trained on artificial traces supports these inputs.
No EventStore initialization, migration, protected-file access, or policy write
is performed here. Callers must hold the registered workspace authority lease.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3
import time

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, identifier


MAX_ROWS = 2048
MAX_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class EventSnapshot:
    workspace_id: str
    session_id: str
    event_id: str
    observed_sequence: int
    input_digest: str
    protection_digest: str
    policy_digest: str


class EventSource:
    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        if self.path.name != 'events.db':
            raise ForecastDataError('invalid_event_database_name')

    def connect(self):
        connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=0.1)
        connection.execute('PRAGMA query_only=ON')
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        deadline = time.monotonic() + 0.5
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        return connection

    def snapshot(self, workspace: str, session: str) -> EventSnapshot:
        identifier(workspace)
        identifier(session)
        with closing(self.connect()) as connection:
            connection.execute('BEGIN')
            latest = connection.execute(
                'SELECT event_id, sequence_no FROM events WHERE workspace_id=? AND session_id=? '
                'ORDER BY sequence_no DESC, event_id DESC LIMIT 1', (workspace, session),
            ).fetchone()
            if latest is None or type(latest[1]) is not int or latest[1] < 0:
                raise ForecastDataError('recording_session_unavailable')
            identifier(latest[0])
            remaining = [MAX_ROWS, MAX_BYTES]

            def fingerprint(queries):
                hasher = hashlib.sha256()
                for sql, params in queries:
                    # Shared limits cover the entire snapshot, including every table.
                    cursor = connection.execute(sql + ' LIMIT ?', (*params, MAX_ROWS + 1))
                    for row in cursor:
                        encoded = canonical(row).encode()
                        remaining[0] -= 1
                        remaining[1] -= len(encoded)
                        if min(remaining) < 0:
                            raise ForecastDataError('recording_snapshot_limit')
                        hasher.update(len(encoded).to_bytes(8, 'big'))
                        hasher.update(encoded)
                    hasher.update(b'\xff')  # Separate tables, including empty ones.
                return hasher.hexdigest()

            scope = (workspace, session)
            inputs = fingerprint([
                ('SELECT * FROM events WHERE workspace_id=? AND session_id=? ORDER BY event_id', scope),
                ('SELECT o.* FROM tool_operations o JOIN events e ON e.event_id=o.event_id '
                 'WHERE e.workspace_id=? AND e.session_id=? ORDER BY o.operation_id', scope),
                ('SELECT o.* FROM tool_operation_outcomes o JOIN events e ON e.event_id=o.post_event_id '
                 'WHERE e.workspace_id=? AND e.session_id=? ORDER BY o.post_event_id,o.operation_id', scope),
                ('SELECT * FROM resource_versions WHERE workspace_id=? AND session_id=? ORDER BY node_id', scope),
                ('SELECT * FROM sink_candidates WHERE workspace_id=? AND session_id=? ORDER BY node_id', scope),
            ])
            protection = fingerprint([
                ('SELECT * FROM protected_sources WHERE workspace_id=? ORDER BY source_id', (workspace,)),
            ])
            policy = fingerprint([
                ('SELECT * FROM workspace_runtime_settings WHERE workspace_id=? ORDER BY workspace_id', (workspace,)),
            ])
            return EventSnapshot(workspace, session, latest[0], latest[1], inputs, protection, policy)
