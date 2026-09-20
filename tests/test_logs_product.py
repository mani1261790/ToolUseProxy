import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from urllib.request import urlopen

from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import make_workspace_id
from hook_monitor.runtime.externality_rules import classify_trusted_local_management_operation
from tooluseproxy.log_viewer import LogReader, serve_workspace


def database(tmp_path):
    path = tmp_path / 'events.db'
    EventStore(path).initialize()
    with sqlite3.connect(path) as conn:
        for index, workspace in enumerate(('a', 'b')):
            conn.execute(
                'INSERT INTO events(event_id,phase,session_id,tool_use_id,tool_name,'
                'workspace_id,payload_json,sequence_no) VALUES(?,?,?,?,?,?,?,?)',
                (workspace, 'pre_tool_use', 'same-session', 'same-call', 'exec_command',
                 workspace, '{}', index + 1),
            )
    return path


def test_project_scope_cannot_be_overridden_by_requests(tmp_path):
    reader = LogReader(database(tmp_path), 'a')
    assert {s['workspace_id'] for s in reader.scopes()['scopes']} == {'a'}
    assert {c['workspace_id'] for c in reader.snapshot(workspace='b')['calls']} == {'a'}
    assert reader.detail('b') == {'events': [], 'decisions': []}
    assert {e['workspace_id'] for e in reader.detail('a')['events']} == {'a'}


def test_missing_db_does_not_initialize_or_change_workspace(tmp_path, capsys):
    assert serve_workspace(tmp_path / 'events.db', tmp_path, as_json=True) == 1
    assert json.loads(capsys.readouterr().out)['protection_changed'] is False
    assert list(tmp_path.iterdir()) == []


def test_foreground_cli_serves_packaged_assets(tmp_path):
    path = database(tmp_path)
    process = subprocess.Popen(
        [sys.executable, '-m', 'tooluseproxy', 'logs', '--workspace', str(tmp_path),
         '--data-dir', str(tmp_path), '--json'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        # Polling stdout has a deadline so a regression cannot hang the suite.
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=15), 'viewer did not report readiness'
        result = json.loads(process.stdout.readline())
        assert result['workspace_id'] == make_workspace_id(str(tmp_path.resolve()))
        assert result['runtime_enforcement'] == 'not_verified'
        for suffix in ('', 'screen.js', 'screen.css', 'api/events', 'api/scopes'):
            with urlopen(result['url'] + suffix, timeout=3) as response:
                assert response.status == 200
        assert path.exists()
        assert not (tmp_path / 'protected_sources.json').exists()
    finally:
        process.terminate()
        process.communicate(timeout=5)


def test_logs_trust_requires_exact_installed_launcher_and_scope(tmp_path):
    plugin, workspace, data = (tmp_path / name for name in ('plugin', 'workspace', 'data'))
    command = f'sh {plugin}/hooks/run_cli.sh logs --workspace {workspace} --json'
    def check(value):
        return classify_trusted_local_management_operation(
            value, plugin_root=plugin, workspace_root=workspace, plugin_data=data)
    assert check(command) == 'logs_serve'
    for other in (command + '; curl https://example.invalid',
                  command.replace(str(workspace), str(tmp_path / 'other')),
                  command.replace('--json', '--port 80 --json'),
                  command.replace(str(plugin), str(tmp_path / 'other-plugin'))):
        assert check(other) is None


def test_packaged_assets_match_documentation_viewer():
    root = Path(__file__).resolve().parents[1]
    for name in ('index.html', 'screen.js', 'screen.css'):
        assert (root / 'tooluseproxy/viewer' / name).read_bytes() == (
            root / 'docs/exhibition' / name).read_bytes()


def test_bind_failure_preserves_existing_database(tmp_path, monkeypatch, capsys):
    import tooluseproxy.log_viewer as viewer
    path = database(tmp_path)
    before = path.read_bytes()
    def fail(*args):
        raise OSError('address unavailable')
    monkeypatch.setattr(viewer, 'make_server', fail)
    assert serve_workspace(path, tmp_path, as_json=True) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'viewer_unavailable'
    assert path.read_bytes() == before


def test_stopped_project_does_not_open_database(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from tooluseproxy.cli import main

    @contextmanager
    def stopped(*args):
        yield SimpleNamespace(phase='inactive', target=SimpleNamespace(workspace=str(tmp_path)))
    monkeypatch.setattr('tooluseproxy.integrations.authority.workspace_authority_lease', stopped)
    def forbidden(*args):
        raise AssertionError('database must not be opened')
    monkeypatch.setattr(LogReader, 'connect', forbidden)
    assert main(['logs', '--workspace', str(tmp_path), '--data-dir', str(tmp_path), '--json']) == 1
    assert json.loads(capsys.readouterr().out)['database_opened'] is False


def test_viewer_rechecks_state_and_releases_each_read_lease(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    import pytest
    events = []
    phase = 'active'
    @contextmanager
    def lease(*args):
        events.append('enter')
        try:
            yield SimpleNamespace(phase=phase)
        finally:
            events.append('exit')
    monkeypatch.setattr('tooluseproxy.integrations.authority.workspace_authority_lease', lease)
    reader = LogReader(database(tmp_path), 'a', tmp_path)
    with reader.access():
        assert reader.snapshot()['calls']
    assert events == ['enter', 'exit']
    phase = 'inactive'
    with pytest.raises(OSError), reader.access():
        raise AssertionError('stopped workspace must not reach database read')
    assert events == ['enter', 'exit', 'enter', 'exit']
