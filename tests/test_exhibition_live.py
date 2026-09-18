from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from hook_monitor.runtime.storage import EventStore
from scripts.serve_exhibition import LogReader, PAYLOAD_LIMIT, make_server


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'events.db'
    EventStore(path).initialize()
    return path


def append(path, event_id='pre', phase='pre_tool_use', sequence=1, session='session-a', **payload):
    with sqlite3.connect(path) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute(
            'INSERT INTO events(event_id,phase,session_id,tool_use_id,tool_name,workspace_id,'
            'payload_json,sequence_no) VALUES(?,?,?,?,?,?,?,?)',
            (event_id, phase, session, 'call-1', 'exec_command', 'workspace-a',
             json.dumps(payload), sequence),
        )


def block(path):
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO sink_candidates(node_id,sink_type,label,sequence_no,workspace_id,metadata_json) "
            "VALUES('sink','http','fixture',1,'workspace-a',?)", (json.dumps({'event_id': 'pre'}),))
        conn.execute(
            "INSERT INTO policy_decisions(decision_id,finding_id,analysis_run_id,hook_event,"
            "action,severity,sink_type,source_node_kind,source_node_id,sink_node_id,path_score,"
            "reason,user_message,technical_summary,trace_command,path_summary_json) "
            "VALUES('decision','finding','run','PreToolUse','block','critical','http',"
            "'source_chunk','source','sink',1,'synthetic block','人工データの送信を停止',"
            "'fixture','fixture','[]')")


def test_live_post_and_late_decision_are_visible_without_restarting(database):
    reader = LogReader(database)
    assert reader.snapshot()['calls'] == []
    append(database, tool_input={'cmd': 'echo synthetic'})
    assert len(reader.snapshot()['calls']) == 1
    assert reader.detail('pre')['events'][0]['payload']['tool_input']['cmd'] == 'echo synthetic'
    append(database, 'post', 'post_tool_use', 2, tool_response={'stdout': 'synthetic'})
    assert len(reader.snapshot()['calls']) == 1
    assert len(reader.detail('pre')['events']) == 2
    block(database)
    assert reader.snapshot()['calls'][0]['blocked'] is True
    assert reader.detail('post')['decisions'][0]['action'] == 'block'


def test_call_ids_do_not_join_different_sessions(database):
    append(database, tool_input={'cmd': 'first'})
    append(database, 'other', 'post_tool_use', 2, session='session-b', tool_response='other')
    reader = LogReader(database)
    assert len(reader.snapshot()['calls']) == 2
    assert len(reader.detail('pre')['events']) == 1
    block(database)
    assert reader.detail('other')['decisions'] == []


def test_readonly_missing_database_and_truncation(database, tmp_path):
    missing = tmp_path / 'missing' / 'events.db'
    with pytest.raises(sqlite3.OperationalError):
        LogReader(missing).snapshot()
    assert not missing.exists()
    append(database, tool_input='x' * (PAYLOAD_LIMIT + 20))
    reader = LogReader(database)
    with reader.connect() as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute('DELETE FROM events')
    result = reader.detail('pre')['events'][0]
    assert result['truncated']
    assert len(result['payload']['saved_text']) == PAYLOAD_LIMIT


def test_server_security_and_recovery(database):
    reader = LogReader(database)
    server, url = make_server(reader)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(url + 'api/events') as response:
            assert json.load(response)['calls'] == []
            assert response.headers['Cache-Control'] == 'no-store'
        append(database, tool_input='<script>synthetic</script>')
        with urlopen(url + 'api/events') as response:
            assert len(json.load(response)['calls']) == 1
        for target, headers in [
            (url + '../events.db', {}),
            (url + 'api/events', {'Origin': 'https://untrusted.invalid'}),
            (url + 'api/events', {'Host': 'untrusted.invalid'}),
        ]:
            with pytest.raises(HTTPError) as error:
                urlopen(Request(target, headers=headers))
            assert error.value.code in (403, 404)
        saved = Path(str(database) + '.saved')
        database.rename(saved)
        with pytest.raises(HTTPError) as error:
            urlopen(url + 'api/events')
        assert error.value.code == 503
        saved.rename(database)
        with urlopen(url + 'api/events') as response:
            assert len(json.load(response)['calls']) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
