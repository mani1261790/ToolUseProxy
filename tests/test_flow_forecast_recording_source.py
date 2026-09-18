from dataclasses import asdict
import sqlite3

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.runtime.storage import EventStore
from research.flow_forecast.recording.source import EventSource


def source(tmp_path):
    path = tmp_path / 'events.db'
    EventStore(path).initialize()
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO events(event_id,phase,workspace_id,session_id,sequence_no,payload_json) "
                     "VALUES('event','pre_tool_use','workspace','session',1,'{}')")
    return EventSource(path)


def test_readonly_snapshot_detects_late_input_and_keeps_payload_local(tmp_path):
    reader = source(tmp_path)
    before = reader.path.read_bytes()
    initial = reader.snapshot('workspace', 'session')
    assert reader.path.read_bytes() == before
    with reader.connect() as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute('DELETE FROM events')
    with sqlite3.connect(reader.path) as conn:
        conn.execute("UPDATE events SET payload_json=? WHERE event_id='event'", ('{"tool_input":"synthetic-private-value"}',))
    updated = reader.snapshot('workspace', 'session')
    assert updated.input_digest != initial.input_digest
    assert updated.observed_sequence == initial.observed_sequence
    assert 'synthetic-private-value' not in str(asdict(updated))
    assert updated.protection_digest == initial.protection_digest


def test_scope_and_settings_changes(tmp_path):
    reader = source(tmp_path)
    initial = reader.snapshot('workspace', 'session')
    with sqlite3.connect(reader.path) as conn:
        conn.execute("INSERT INTO events(event_id,phase,workspace_id,session_id,sequence_no,payload_json) "
                     "VALUES('other','pre_tool_use','other','session',2,'{}')")
    assert reader.snapshot('workspace', 'session') == initial
    with sqlite3.connect(reader.path) as conn:
        conn.execute("INSERT INTO workspace_runtime_settings VALUES(?,1,?,'{}','now')", ('workspace', 'a' * 64))
    assert reader.snapshot('workspace', 'session').policy_digest != initial.policy_digest
    with sqlite3.connect(reader.path) as conn:
        conn.execute("INSERT INTO protected_sources(source_id,path,source_type,sensitivity,policy_tags_json,workspace_id) "
                     "VALUES('source','synthetic','file','high','[]','workspace')")
    assert reader.snapshot('workspace', 'session').protection_digest != initial.protection_digest
    with pytest.raises(ForecastDataError, match='session_unavailable'):
        reader.snapshot('workspace', 'missing')


def test_missing_database_is_not_created_and_overflow_is_not_truncated(tmp_path, monkeypatch):
    missing = tmp_path / 'missing' / 'events.db'
    with pytest.raises(sqlite3.OperationalError):
        EventSource(missing).snapshot('workspace', 'session')
    assert not missing.exists()
    reader = source(tmp_path)
    monkeypatch.setattr('research.flow_forecast.recording.source.MAX_ROWS', 0)
    with pytest.raises(ForecastDataError, match='snapshot_limit'):
        reader.snapshot('workspace', 'session')


def test_late_candidate_and_resource_revision_invalidate_snapshot(tmp_path):
    reader = source(tmp_path)
    initial = reader.snapshot('workspace', 'session')
    with sqlite3.connect(reader.path) as conn:
        conn.execute("INSERT INTO sink_candidates(node_id,sink_type,label,sequence_no,metadata_json,workspace_id,session_id) "
                     "VALUES('sink','http','synthetic',1,'{}','workspace','session')")
    candidate = reader.snapshot('workspace', 'session')
    assert candidate.input_digest != initial.input_digest
    assert candidate.observed_sequence == initial.observed_sequence
    with sqlite3.connect(reader.path) as conn:
        conn.execute("UPDATE sink_candidates SET metadata_json=? WHERE node_id='sink'", ('{"input_revision":2}',))
    updated = reader.snapshot('workspace', 'session')
    assert updated.input_digest != candidate.input_digest
    with sqlite3.connect(reader.path) as conn:
        conn.execute("INSERT INTO resource_versions(node_id,path,content_hash,sequence_no,session_id,workspace_id) "
                     "VALUES('resource','synthetic','version1',1,'session','workspace')")
    resource = reader.snapshot('workspace', 'session')
    assert resource.input_digest != updated.input_digest
    with sqlite3.connect(reader.path) as conn:
        conn.execute("UPDATE resource_versions SET content_hash='version2' WHERE node_id='resource'")
    assert reader.snapshot('workspace', 'session').input_digest != resource.input_digest
