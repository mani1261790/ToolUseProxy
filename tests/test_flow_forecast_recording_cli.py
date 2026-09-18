from contextlib import contextmanager
import json
import sqlite3

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import write_dataset
from research.flow_forecast.artifacts import save_model
from research.flow_forecast.model import fit
from research.flow_forecast.recording.cli import main, inspect_input
from research.flow_forecast.recording.source import EventSource
from test_flow_forecast_baselines import dataset
from test_flow_forecast_recording_source import source as event_source


def test_cli_roundtrip_real_child_disable_and_preserved_history(tmp_path, capsys):
    data = dataset()
    directory, model = tmp_path / 'dataset', tmp_path / 'model.json'
    write_dataset(data, directory)
    save_model(fit(data), model)
    journal = tmp_path / 'forecast.db'
    common = ['--journal', str(journal), '--synthetic-dataset', str(directory)]
    def invoke(command, *extra):
        assert main([command, *common, *extra]) == 0
        return json.loads(capsys.readouterr().out)
    assert main(['init', '--journal', str(journal)]) == 0
    assert not json.loads(capsys.readouterr().out)['enabled']
    assert invoke('run', '--model', str(model))['status'] == 'unconfigured'
    assert invoke('enable')['status'] == 'enabled'
    candidate = invoke('candidates')['candidates'][0]['candidate']
    assert invoke('enqueue', '--model', str(model), '--candidate', candidate)['status'] == 'pending'
    assert invoke('run', '--model', str(model))['status'] == 'recorded'
    history = invoke('history')
    assert history['synthetic_only'] and history['historical_only']
    assert history['records'][0]['result']['record_only']
    assert invoke('disable')['status'] == 'disabled'
    assert invoke('history')['status'] == 'unconfigured'
    assert invoke('enable')['generation'] == 3
    assert invoke('history')['records'] == history['records']
    assert invoke('recover')['interrupted'] == 0


def test_fresh_source_failure_and_model_missing_are_not_predictions(tmp_path, capsys):
    data = dataset()
    directory, model = tmp_path / 'dataset', tmp_path / 'model.json'
    write_dataset(data, directory)
    save_model(fit(data), model)
    journal = tmp_path / 'forecast.db'
    common = ['--journal', str(journal), '--synthetic-dataset', str(directory)]
    main(['init', '--journal', str(journal)])
    main(['enable', *common])
    candidate = data.prefixes[0].prefix_id
    main(['enqueue', *common, '--model', str(model), '--candidate', candidate])
    capsys.readouterr()
    model.rename(tmp_path / 'saved-model.json')
    assert main(['run', *common, '--model', str(model)]) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'model_missing'
    main(['history', *common])
    assert json.loads(capsys.readouterr().out)['records'][0]['result'] is None


def test_registered_inspection_holds_lease_and_never_writes(tmp_path, monkeypatch):
    reader = event_source(tmp_path)
    original = reader.path.read_bytes()
    inside = []
    @contextmanager
    def lease(database, connection, workspace):
        assert database == reader.path and workspace == 'workspace'
        with pytest.raises(sqlite3.OperationalError):
            connection.execute('DELETE FROM events')
        inside.append(True)
        try:
            yield None
        finally:
            inside.pop()
    original_snapshot = EventSource.snapshot
    def snapshot(self, *args):
        assert inside
        return original_snapshot(self, *args)
    monkeypatch.setattr('research.flow_forecast.recording.cli.registered_workspace_authority_lease', lease)
    monkeypatch.setattr(EventSource, 'snapshot', snapshot)
    result = inspect_input(reader.path, 'workspace', 'session')
    assert result['status'] == 'out_of_domain' and result['prediction'] is None
    assert reader.path.read_bytes() == original and not inside


def test_inactive_inspection_does_not_read_input(tmp_path, monkeypatch):
    reader = event_source(tmp_path)
    @contextmanager
    def lease(*args):
        yield type('State', (), {'phase': 'inactive'})()
    def forbidden(*args):
        raise AssertionError('inactive input must not be read')
    monkeypatch.setattr('research.flow_forecast.recording.cli.registered_workspace_authority_lease', lease)
    monkeypatch.setattr(EventSource, 'snapshot', forbidden)
    assert inspect_input(reader.path, 'workspace', 'session') == {'status': 'administratively_inactive'}


def test_actual_authority_store_drains_inspection_and_rejects_next_one(tmp_path, monkeypatch):
    import os
    from hook_monitor.runtime.storage import EventStore
    from hook_monitor.runtime.workspace import make_workspace_id
    from tooluseproxy.authority_state import Target, _Store

    directory = tmp_path / 'authority'
    directory.mkdir(mode=0o755)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    database = data_dir / 'events.db'
    EventStore(database).initialize()
    identity = make_workspace_id(str(workspace))
    with sqlite3.connect(database) as connection:
        connection.execute('INSERT INTO workspaces(workspace_id,canonical_root,lexical_root,discovered_by) VALUES(?,?,?,?)',
                           (identity, str(workspace), str(workspace), 'synthetic-test'))
    store = _Store(directory, owner=os.geteuid())
    target = Target(os.getuid(), str(workspace), str(data_dir))
    enrolled = store.transition(target, expected='absent', operation='a' * 32, action='enroll')
    monkeypatch.setattr('tooluseproxy.authority_state.AUTHORITY_DIRECTORY', directory)
    monkeypatch.setattr('tooluseproxy.integrations.authority._Store', lambda _: store)
    states = []
    def interrupted(*args):
        state = store.transition(target, expected=enrolled.generation, operation='b' * 32, action='deactivate')
        states.append(state)
        assert state.phase == 'deactivating'
        raise sqlite3.OperationalError('synthetic interruption')
    monkeypatch.setattr(EventSource, 'snapshot', interrupted)
    with pytest.raises(sqlite3.OperationalError):
        inspect_input(database, identity, 'session')
    inactive = store.transition(target, expected=states[0].generation, operation='b' * 32, action='deactivate')
    assert inactive.phase == 'inactive'
    assert inspect_input(database, identity, 'session')['status'] == 'administratively_inactive'


def test_history_explanation_keeps_unknown_and_absent_results_distinct():
    from research.flow_forecast.recording.explain import history_text
    text = history_text([{'request_id': 'request', 'status': 'recorded', 'result': {
        'binding': {'observed_sequence': 2}, 'forecast': {
            'horizon': 4, 'model_version': 'test-model', 'policy_mode': 'observe',
            'protected_probability': None, 'unknown_probability': 1.0,
            'other_probability': 0, 'outcomes': [],
        },
    }}, {'request_id': 'other', 'status': 'expired', 'result': None}])
    assert '到達確率: 未確定' in text
    assert '未解決の確率: 100.0%' in text
    assert '有効期限切れ' in text and '予測結果なし' in text
    assert '現在の安全性や操作の許可を示すものではありません' in text
