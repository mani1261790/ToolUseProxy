import subprocess

import pytest

from tooluseproxy.engine.invocation_context import observe, unchanged
from tooluseproxy.engine.evidence import EvidenceStore
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.payload import PayloadResolver
from tooluseproxy.engine.targets import inspect_transmission


@pytest.fixture
def repository(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    root = tmp_path / 'repo'
    root.mkdir()
    for name in list(__import__('os').environ):
        if name.startswith('GIT_'):
            monkeypatch.delenv(name)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(home / '.config'))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)
    records = dict(tool_name='Bash', tool_input={'command': 'git push'},
                   resolved_cwd=str(root), workspace_root=str(root))
    return root, home, records


def test_inherited_settings_and_environment_are_fresh(repository, monkeypatch):
    root, home, records = repository
    config = home / '.gitconfig'
    config.write_text('[push]\n default = current\n[remote "origin"]\n url = https://example.invalid/one\n')
    receipt = observe(records)
    assert receipt['status'] == 'observed'
    assert receipt['facts']['head_ref'] == 'refs/heads/main'
    assert {'key': 'push.default', 'value': 'current'} in receipt['facts']['settings']
    records['invocation_context'] = receipt
    assert unchanged(records)
    local_before = (root / '.git/config').read_bytes()
    config.write_text(config.read_text().replace('/one', '/two'))
    assert not unchanged(records)
    assert (root / '.git/config').read_bytes() == local_before
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'push.default')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'matching')
    settings = observe(records)['facts']['settings']
    assert [s['value'] for s in settings if s['key'] == 'push.default'] == ['current', 'matching']


def test_unresolved_includes_are_not_default_settings(repository):
    _, home, records = repository
    (home / '.gitconfig').write_text('[include]\n path = /never/open/this\n')
    receipt = observe(records)
    assert receipt['status'] == 'unavailable'
    assert receipt['reason'] == 'context_config_includes_unresolved'
    assert receipt['facts'] == {}
    assert not unchanged({**records, 'invocation_context': receipt})


def test_context_only_applies_to_understood_invocation(repository):
    _, _, records = repository
    for command in ('python script.py', 'git -c push.default=matching push', 'git push; echo done'):
        assert observe({**records, 'tool_input': {'command': command}}) is None


def test_control_file_override_is_rejected_before_any_read(repository, monkeypatch):
    root, _, records = repository
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(root / 'protected_sources.json'))

    def forbidden(*args, **kwargs):
        pytest.fail('must not open configuration when it names forbidden control state')

    monkeypatch.setattr('tooluseproxy.engine.invocation_context.bounded_read', forbidden)
    assert observe(records)['reason'] == 'context_control_state_forbidden'


def test_current_branch_and_invocation_changes_invalidate_receipt(repository):
    root, _, records = repository
    records['invocation_context'] = observe(records)
    assert unchanged(records)
    subprocess.run(['git', '-C', str(root), 'symbolic-ref', 'HEAD', 'refs/heads/other'], check=True)
    assert not unchanged(records)
    records['invocation_context'] = observe(records)
    assert not unchanged({**records, 'tool_input': {'command': 'git push origin other'}})


def test_context_bytes_and_freshness_are_bound_to_resolution(repository, tmp_path):
    root, home, records = repository
    path = home / '.gitconfig'
    path.write_text('[remote "origin"]\n url = https://example.invalid/one\n')
    journal = Journal(tmp_path / 'events.db')
    journal.initialize()
    event = event_from('pre_tool_use', dict(cwd=str(root), session_id='one',
                       tool_use_id='send', tool_name='Bash', tool_input=records['tool_input']), str(root))
    journal.record(event)
    resolver = PayloadResolver(EvidenceStore(journal.db_path), event.workspace_id, event.event_id, root)
    resolver.definition_context = {**records, 'invocation_context': observe(records)}
    target = dict(kind='context', pointer='/invocation_context/facts/settings/0/value')
    result = resolver.resolve(target)
    assert result.coverage == 'complete'
    assert result.parts[0].content == b'https://example.invalid/one'
    assert result.parts[0].version.resource.kind == 'invocation_context'
    assert resolver.unchanged(result)
    path.write_text('[remote "origin"]\n url = https://example.invalid/two\n')
    assert not resolver.unchanged(result)
    assert resolver.resolve(dict(kind='context', pointer='/invocation_context/boundary')).coverage != 'complete'


def test_plan_reuse_invalidates_on_inherited_context_change(repository, tmp_path):
    root, home, records = repository
    path = home / '.gitconfig'
    path.write_text('[remote "origin"]\n url = https://example.invalid/one\n')
    journal = Journal(tmp_path / 'events.db')
    journal.initialize()
    calls = []

    def provider(packet):
        calls.append(packet['invocation_context'])
        return dict(complete=True, reason='current destination', targets=[dict(kind='context',
                    pointer='/invocation_context/facts/settings/0/value', path=None,
                    offset=0, length=None, format=None, revision=None, reason='remote destination')])

    def inspect(number):
        event = event_from('pre_tool_use', dict(cwd=str(root), session_id='one',
                           tool_use_id=str(number), tool_name='Bash', tool_input=records['tool_input']), str(root))
        journal.record(event)
        return inspect_transmission(journal, event, provider)[1]

    assert inspect(1).parts[0].content.endswith(b'/one')
    assert inspect(2).parts[0].content.endswith(b'/one')
    assert len(calls) == 1
    path.write_text('[remote "origin"]\n url = https://example.invalid/two\n')
    assert inspect(3).parts[0].content.endswith(b'/two')
    assert len(calls) == 2
