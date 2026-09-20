"""Artificial database and real Hook/worker boundary; no host runtime activation."""
from dataclasses import replace
import io
import json
import sqlite3
import threading
import time
from unittest.mock import patch

import pytest

from hook_monitor.runtime.forecast import bridge
from hook_monitor.runtime.forecast.journal import Journal
from hook_monitor.runtime.forecast.source import canonical, digest, snapshot
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.parser import build_artifacts, build_fragments, normalize_event
from hook_monitor.runtime.runner import run_hook
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from research.flow_forecast.model import SequenceModel
from research.flow_forecast.runtime_worker import prefix_from_structure, prediction, run_one
from research.flow_forecast.tokens import Action, END, advance, context
from tooluseproxy.forecast_cli import main


@pytest.fixture
def environment(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    database = tmp_path / 'events.db'
    store = EventStore(database)
    store.initialize()
    workspace = resolve_workspace(str(root), str(root))
    store.register_workspace(workspace)
    with sqlite3.connect(database) as conn:
        conn.execute('INSERT INTO protected_sources(source_id,path,source_type,sensitivity,policy_tags_json,workspace_id) '
                     'VALUES(?,?,?,?,?,?)', ('fixture-source', str(root / 'fixture-private.txt'), 'file', 'high', '[]', workspace.workspace_id))
    return database, root, workspace, Journal.create(tmp_path / 'forecast.db')


def record(environment, *, session='session', call='candidate', command='./opaque', phase='pre_tool_use'):
    database, root, _, _ = environment
    payload = {'session_id': session, 'tool_use_id': call, 'tool_name': 'Bash', 'cwd': str(root),
               'tool_input': {'command': command}}
    event = normalize_event(phase, payload, workspace_root=str(root))
    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    extraction = extract_tool_operations(event, artifacts, fragments)
    EventStore(database).record(event, artifacts, fragments + list(extraction.fragments), list(extraction.operations))
    return event


def positive_model(structure):
    """Deliberate positive fixture model; no efficacy claim."""
    prefix = prefix_from_structure(structure)
    action = Action('http', 'send', 'send', (('source', 0),), ('sink',), ((0, 0, 'send'),))
    following, _ = advance(prefix, action)
    return SequenceModel({context(prefix, 'enforce'): ((action, 1.),),
                          context(following, 'enforce'): ((END, 1.),)}, 'a' * 64, ('fixture',))


def prepared(environment, mode='stop'):
    database, _, workspace, journal = environment
    event = record(environment)
    structure = snapshot(database, workspace.workspace_id, event.session_id, event.event_id)
    model = positive_model(structure)
    journal.configure(workspace.workspace_id, mode, model.model_digest, .5)
    return event, structure, model


def test_snapshot_is_value_free_and_excludes_pending_and_other_sessions(environment):
    database, _, workspace, _ = environment
    first = record(environment, command='echo synthetic-private-marker')
    structure = snapshot(database, workspace.workspace_id, first.session_id, first.event_id)
    assert structure['observations'] == []
    assert 'synthetic-private-marker' not in canonical(structure)
    record(environment, session='other', call='parallel')
    assert snapshot(database, workspace.workspace_id, first.session_id, first.event_id) == structure
    with sqlite3.connect(database) as conn:
        conn.execute('UPDATE events SET payload_json=? WHERE event_id=?', ('{"tool_input":"changed"}', first.event_id))
    assert snapshot(database, workspace.workspace_id, first.session_id, first.event_id) != structure
    following = record(environment, call='later')
    assert following.event_id != first.event_id
    with pytest.raises(ValueError, match='candidate_changed'):
        snapshot(database, workspace.workspace_id, first.session_id, first.event_id)


def test_completed_file_read_becomes_structural_observation(environment):
    database, root, workspace, _ = environment
    event = record(environment, command=f'cat {root / "fixture-private.txt"}', call='read')
    with sqlite3.connect(database) as conn:
        operation = conn.execute('SELECT operation_id FROM tool_operations WHERE event_id=?', (event.event_id,)).fetchone()[0]
        conn.execute("INSERT INTO events(event_id,phase,session_id,workspace_id,sequence_no,payload_json) VALUES('post','post_tool_use','session',?,2,'{}')", (workspace.workspace_id,))
        conn.execute("INSERT INTO tool_operation_outcomes(post_event_id,operation_id,outcome) VALUES('post',?,'succeeded')", (operation,))
    candidate = record(environment, call='next')
    structure = snapshot(database, workspace.workspace_id, candidate.session_id, candidate.event_id)
    prefix = prefix_from_structure(structure)
    assert len(prefix.observations) == 1 and prefix.observations[0].operation == 'read'
    assert prefix.observations[0].inputs == prefix.protected_sources
    assert prefix.max_sequence_no == 1
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE tool_operation_outcomes SET outcome='unknown'")
    with pytest.raises(ValueError, match='unsupported'):
        prefix_from_structure(snapshot(database, workspace.workspace_id, candidate.session_id, candidate.event_id))


def test_queue_worker_actual_prediction_and_model_binding(environment):
    database, _, workspace, journal = environment
    event, structure, model = prepared(environment)
    config = journal.configuration(workspace.workspace_id)
    request = journal.enqueue(structure, config)
    assert run_one(database, model) == 'predicted'
    result = journal.get(request)
    assert json.loads(result['result'])['probability'] == 1
    assert result['state'] == 'ready'
    journal.configure(workspace.workspace_id, 'record', 'f' * 64, .5)
    other = journal.enqueue(structure, journal.configuration(workspace.workspace_id))
    assert run_one(database, model) == 'idle'
    assert journal.get(other)['state'] == 'pending'  # A worker for another model cannot steal it.


@pytest.mark.parametrize('change', ['session', 'input', 'protection', 'policy', 'disable'])
def test_worker_discards_changes_during_prediction(environment, change):
    database, _, workspace, journal = environment
    event, structure, model = prepared(environment)
    request = journal.enqueue(structure, journal.configuration(workspace.workspace_id))
    def changed(model, structure):
        if change == 'disable':
            journal.configure(workspace.workspace_id, 'off', model.model_digest, .5)
        else:
            with sqlite3.connect(database) as conn:
                if change == 'session':
                    conn.execute('UPDATE events SET session_id=? WHERE event_id=?', ('other', event.event_id))
                elif change == 'input':
                    conn.execute('UPDATE events SET payload_json=? WHERE event_id=?', ('{"changed":true}', event.event_id))
                elif change == 'protection':
                    conn.execute("UPDATE protected_sources SET sensitivity='changed'")
                else:
                    conn.execute('INSERT INTO workspace_runtime_settings VALUES(?,1,?,\'{}\',\'now\')', (workspace.workspace_id, 'f' * 64))
        return prediction(model, structure)
    assert run_one(database, model, predict=changed) in {'stale', 'failed'}
    result = journal.get(request)
    assert result['result'] is None or json.loads(result['result'])['status'] != 'predicted'


def test_expiry_missing_worker_and_existing_block(environment):
    database, _, workspace, journal = environment
    event, structure, model = prepared(environment)
    existing = {'hookSpecificOutput': {'permissionDecision': 'deny', 'permissionDecisionReason': 'existing'}}
    assert bridge.apply_forecast(database, event, existing) is existing
    assert journal.history(workspace.workspace_id) == []
    start = time.monotonic()
    assert bridge.apply_forecast(database, event, None) is None
    assert time.monotonic() - start < .75
    assert journal.history(workspace.workspace_id)[0]['application'] == 'timeout'
    journal.configure(workspace.workspace_id, 'stop', model.model_digest, .5)
    old = journal.enqueue(structure, journal.configuration(workspace.workspace_id), now=time.time() - 3)
    assert run_one(database, model) == 'idle'
    assert journal.get(old)['state'] == 'expired'


def test_record_mode_does_not_wait_or_stop(environment):
    database, _, workspace, journal = environment
    event, _, model = prepared(environment, mode='record')
    assert bridge.apply_forecast(database, event, None) is None
    assert journal.history(workspace.workspace_id)[0]['application'] == 'record_only'
    assert run_one(database, model) == 'predicted'
    assert bridge.apply_forecast(database, replace(event, session_id='other'), None) is None


def test_real_hook_and_worker_emit_additional_deny(environment, monkeypatch):
    database, root, workspace, journal = environment
    # Build a fixture model before invocation, using the same visible empty history.
    fixture = {'schema': 1, 'workspace': workspace.workspace_id, 'session': 'session',
               'observations': [], 'protected_paths': [digest(str(root / 'fixture-private.txt'))]}
    model = positive_model(fixture)
    journal.configure(workspace.workspace_id, 'stop', model.model_digest, .5)
    payload = {'session_id': 'session', 'tool_use_id': 'hook-candidate', 'tool_name': 'Bash',
               'cwd': str(root), 'tool_input': {'command': './opaque'}}
    monkeypatch.setenv('TOOLUSEPROXY_WORKSPACE_ROOT', str(root))
    monkeypatch.setenv('TOOLUSEPROXY_PRE_TOOL_POLICY', '1')
    stop = threading.Event()
    errors = []
    def worker():
        try:
            while not stop.is_set():
                run_one(database, model)
                time.sleep(.001)
        except Exception as exc:
            errors.append(type(exc).__name__)
    thread = threading.Thread(target=worker)
    thread.start()
    try:
        stdin = type('Input', (), {'buffer': io.BytesIO(json.dumps(payload).encode())})()
        with patch('sys.stdin', stdin), patch('sys.stdout', new_callable=io.StringIO) as output:
            assert run_hook('pre_tool_use', db_path=database, allow_schema_migration=False) == 0
        result = json.loads(output.getvalue())
        assert result['hookSpecificOutput']['permissionDecision'] == 'deny'
        assert '将来予測' in result['hookSpecificOutput']['permissionDecisionReason']
        assert journal.history(workspace.workspace_id)[0]['application'] == 'additional_stop'
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not errors and not thread.is_alive()


def test_cli_requires_registered_workspace_and_explicit_model(environment, capsys):
    database, _, workspace, journal = environment
    assert main(['--events-db', str(database), 'configure', '--workspace', 'other', '--mode', 'stop', '--model-digest', 'a' * 64]) == 1
    assert journal.configuration('other') is None
    assert main(['--events-db', str(database), 'configure', '--workspace', workspace.workspace_id, '--mode', 'record', '--model-digest', 'a' * 64]) == 0
    assert main(['--events-db', str(database), 'history', '--workspace', workspace.workspace_id]) == 0
    assert 'records' in capsys.readouterr().out


def test_default_does_not_create_journal_or_read_structure(tmp_path, monkeypatch):
    event = type('Event', (), {'workspace_id': 'workspace', 'session_id': 'session'})()
    monkeypatch.setattr(bridge, 'snapshot', lambda *args: pytest.fail('default read'))
    assert bridge.apply_forecast(tmp_path / 'events.db', event, None) is None
    assert not (tmp_path / 'forecast.db').exists()


def test_disable_at_final_consumption_and_single_use(environment):
    database, _, workspace, journal = environment
    _, structure, model = prepared(environment)
    config = journal.configuration(workspace.workspace_id)
    request = journal.enqueue(structure, config)
    assert run_one(database, model) == 'predicted'
    assert journal.consume_stop(request, config)
    assert not journal.consume_stop(request, config)
    journal.configure(workspace.workspace_id, 'stop', model.model_digest, .5)
    config = journal.configuration(workspace.workspace_id)
    request = journal.enqueue(structure, config)
    assert run_one(database, model) == 'predicted'
    journal.configure(workspace.workspace_id, 'off', model.model_digest, .5)
    assert not journal.consume_stop(request, config)


def test_separate_worker_cli_loads_artifact_and_records_result(environment):
    import subprocess
    import sys
    from research.flow_forecast.artifacts import save_model

    database, _, workspace, journal = environment
    _, structure, model = prepared(environment)
    model_path = database.parent / 'model.json'
    save_model(model, model_path)
    request = journal.enqueue(structure, journal.configuration(workspace.workspace_id))
    completed = subprocess.run([sys.executable, '-m', 'tooluseproxy.forecast_cli', '--events-db', str(database),
                                'worker', '--model', str(model_path), '--seconds', '.2'],
                               capture_output=True, timeout=5, check=False)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)['processed'] == 1
    assert json.loads(journal.get(request)['result'])['probability'] == 1


def test_locked_or_corrupt_journal_preserves_prior_decision(environment):
    database, _, workspace, journal = environment
    event, _, _ = prepared(environment)
    existing = {'hookSpecificOutput': {'permissionDecision': 'ask', 'permissionDecisionReason': 'existing'}}
    with sqlite3.connect(journal.path) as conn:
        conn.execute('BEGIN EXCLUSIVE')
        assert bridge.apply_forecast(database, event, existing) is existing
    journal.path.write_bytes(b'invalid artificial database')
    assert bridge.apply_forecast(database, event, existing) is existing


def test_missing_post_is_not_invented_as_observed_success(environment):
    database, _, workspace, _ = environment
    record(environment, call='unfinished', command='cat fixture-private.txt')
    candidate = record(environment, call='next')
    structure = snapshot(database, workspace.workspace_id, candidate.session_id, candidate.event_id)
    assert structure['observations'] == [{'operation': 'unknown'}]
    with pytest.raises(ValueError, match='unsupported'):
        prefix_from_structure(structure)


def test_viewer_displays_only_applied_forecast_stops_and_preserves_history(environment):
    from scripts.serve_exhibition import LogReader

    database, _, workspace, journal = environment
    event, structure, model = prepared(environment)
    config = journal.configuration(workspace.workspace_id)
    request = journal.enqueue(structure, config)
    assert run_one(database, model) == 'predicted'
    reader = LogReader(database)
    assert reader.snapshot(blocked_only=True)['calls'] == []
    assert journal.consume_stop(request, config)
    calls = reader.snapshot(blocked_only=True)['calls']
    assert len(calls) == 1 and calls[0]['event_id'] == event.event_id
    assert calls[0]['blocked']
    assert reader.snapshot(session='other', blocked_only=True)['calls'] == []
    assert reader.detail(event.event_id)['decisions'][0]['reason'] == 'forecast_experimental_stop'
    journal.configure(workspace.workspace_id, 'off', model.model_digest, .5)
    assert len(reader.snapshot(blocked_only=True)['calls']) == 1


def test_completed_history_survives_expiry_and_disable(environment):
    database, _, workspace, journal = environment
    _, structure, model = prepared(environment)
    config = journal.configuration(workspace.workspace_id)
    request = journal.enqueue(structure, config)
    assert run_one(database, model) == 'predicted'
    assert journal.consume_stop(request, config)
    with sqlite3.connect(journal.path) as conn:
        conn.execute('UPDATE requests SET expires=?', (time.time() - 1,))
    assert run_one(database, model) == 'idle'
    journal.configure(workspace.workspace_id, 'off', model.model_digest, .5)
    row = journal.history(workspace.workspace_id)[0]
    assert row['application'] == 'additional_stop'
    assert json.loads(row['result'])['probability'] == 1
    assert row['session_id'] == structure['session']


def test_snapshot_limit_rejects_instead_of_silently_truncating(environment, monkeypatch):
    from hook_monitor.runtime.forecast import source
    database, _, workspace, _ = environment
    candidate = record(environment)
    monkeypatch.setattr(source, 'MAX_ROWS', 0)
    with pytest.raises(ValueError, match='snapshot_limit'):
        snapshot(database, workspace.workspace_id, candidate.session_id, candidate.event_id)


def test_forecast_off_preserves_normal_hook(environment, monkeypatch):
    database, root, workspace, journal = environment
    journal.configure(workspace.workspace_id, 'off', 'a' * 64, .5)
    payload = {'session_id': 'off-session', 'tool_use_id': 'normal', 'tool_name': 'Bash',
               'cwd': str(root), 'tool_input': {'command': 'printf public'}}
    monkeypatch.setenv('TOOLUSEPROXY_WORKSPACE_ROOT', str(root))
    monkeypatch.setenv('TOOLUSEPROXY_PRE_TOOL_POLICY', '1')
    stdin = type('Input', (), {'buffer': io.BytesIO(json.dumps(payload).encode())})()
    with patch('sys.stdin', stdin), patch('sys.stdout', new_callable=io.StringIO) as output:
        assert run_hook('pre_tool_use', db_path=database, allow_schema_migration=False) == 0
    assert output.getvalue() == ''
    assert journal.history(workspace.workspace_id) == []
