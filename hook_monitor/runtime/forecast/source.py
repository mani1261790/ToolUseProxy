"""Read a bounded structural snapshot; never read files named by an event.

Hashes bind the input, not its truth or its suitability for a trained model.
Only completed prior operations become observations. The pending call is separate.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

MAX_ROWS = 200
MAX_BYTES = 2 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def connect(path, *, seconds=.05):
    conn = sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro', uri=True, timeout=.01)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only=ON')
    conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
    deadline = time.monotonic() + seconds
    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
    return conn


def snapshot(database, workspace, session, event_id):
    with closing(connect(database)) as conn:
        conn.execute('BEGIN')
        budget = MAX_BYTES

        def rows(sql, params):
            nonlocal budget
            result = []
            for row in conn.execute(sql + ' LIMIT ?', (*params, MAX_ROWS + 1)):
                item = dict(row)
                budget -= len(canonical(item).encode())
                result.append(item)
                if budget < 0 or len(result) > MAX_ROWS:
                    raise ValueError('forecast_snapshot_limit')
            return result

        registered = rows('SELECT * FROM workspaces WHERE workspace_id=?', (workspace,))
        if len(registered) != 1:
            raise ValueError('forecast_workspace_unregistered')
        events = rows('SELECT event_id,phase,tool_use_id,tool_name,sequence_no,payload_json,workspace_execution_cwd '
                      'FROM events INDEXED BY idx_events_workspace_session_sequence '
                      'WHERE workspace_id=? AND session_id=? ORDER BY sequence_no,event_id', (workspace, session))
        if not events or events[-1]['event_id'] != event_id or events[-1]['phase'] != 'pre_tool_use':
            raise ValueError('forecast_candidate_changed')
        candidate = events[-1]
        scope = (workspace, session)
        operations = rows('SELECT o.* FROM tool_operations o JOIN events e ON e.event_id=o.event_id '
                          'WHERE e.workspace_id=? AND e.session_id=? ORDER BY e.sequence_no,o.operation_index,o.operation_id', scope)
        outcomes = rows('SELECT o.*,e.sequence_no FROM tool_operation_outcomes o JOIN events e ON e.event_id=o.post_event_id '
                        'WHERE e.workspace_id=? AND e.session_id=? ORDER BY e.sequence_no,o.operation_id', scope)
        sources = rows('SELECT * FROM protected_sources WHERE workspace_id=? ORDER BY source_id', (workspace,))
        settings = rows('SELECT * FROM workspace_runtime_settings WHERE workspace_id=?', (workspace,))
        # Same-sequence changes to the existing analysis must also invalidate a result.
        resources = rows('SELECT * FROM resource_versions WHERE workspace_id=? AND session_id=? ORDER BY node_id', scope)
        sinks = rows('SELECT * FROM sink_candidates WHERE workspace_id=? AND session_id=? ORDER BY node_id', scope)
        input_digest = digest([events, operations, outcomes, resources, sinks])
        root = registered[0]['canonical_root']

        def path_key(path, base=None):
            if not isinstance(path, str) or not path:
                return None
            # Lexical identity only. No resolve(), stat(), or protected-file reads.
            return digest(os.path.normpath(path if os.path.isabs(path) else os.path.join(base or root, path)))

        protected = sorted({path_key(s['path']) for s in sources if s['path']})
        observed = []
        for event in events[:-1]:
            if event['phase'] != 'pre_tool_use':
                continue
            ops = [op for op in operations if op['event_id'] == event['event_id']]
            completed = [o for o in outcomes if any(o['operation_id'] == op['operation_id'] for op in ops)]
            if (not ops or any(not any(o['operation_id'] == op['operation_id'] for o in completed) for op in ops)
                    or any(o['outcome'] != 'succeeded' for o in completed)):
                # A missing PostToolUse, opaque call, or failure is never a successful read.
                observed.append({'operation': 'unknown'})
                continue
            for op in ops:
                observed.append({'operation': op['operation_kind'], 'adapter': op['adapter'],
                                 'source': path_key(op['source_path'], event['workspace_execution_cwd']),
                                 'target': path_key(op['target_path'], event['workspace_execution_cwd'])})
        return {'schema': 1, 'workspace': workspace, 'session': session, 'event': event_id,
                'candidate': digest([candidate['tool_use_id'], candidate['tool_name'], candidate['payload_json']]),
                'input': input_digest, 'protection': digest(sources), 'policy': digest([registered, settings]),
                'sequence': candidate['sequence_no'], 'protected_paths': protected, 'observations': observed}
