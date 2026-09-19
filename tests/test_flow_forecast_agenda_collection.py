import json
from copy import deepcopy
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY
from research.flow_forecast import agenda_collection as batch
from research.flow_forecast import agenda_transport as module


def transport(mode='enforce'):
    value = module.AgendaTransport('sha256:fixture', 'public', mode)
    value.address = '172.30.0.2'
    value.check_network = lambda: None
    value.inspect = lambda *a, **k: None
    return value


def test_guard_consumes_exact_json_and_mutation_cannot_dispatch(monkeypatch):
    value = transport()
    step = 'a' * 32
    call = value.prepare_step(1, step)
    calls = []
    def command(argv, *, data=None, **kwargs):
        calls.append((argv, json.loads(data)))
        return canonical({'decision': 'deny', 'receipt_count': 1, 'exit_code': 0,
                          'cause_digest': None, 'cause_trace': [], 'decision_reason': 'fixture'}).encode()
    monkeypatch.setattr(module, 'command', command)
    assert value.guard_step(call, 'b' * 32, step) == 'deny'
    assert calls[0][1]['call'] == call
    script = calls[0][0][-1]
    assert "'tool_name':request['call']['name']" in script
    assert "'tool_input':request['call']['arguments']" in script
    with pytest.raises(LabError, match='denied_agenda'):
        value.execute_step(call, step)
    changed = deepcopy(call)
    changed['arguments']['title'] = 'different'
    with pytest.raises(LabError, match='unprepared_agenda'):
        value.guard_step(changed, 'b' * 32, step)
    assert len(calls) == 1
    assert not value.attempted
    with pytest.raises(LabError, match='invalid_stateful_order'):
        value.prepare_step(2, 'c' * 32)


def test_sender_body_is_read_from_actual_previous_output(monkeypatch):
    value = transport('observe')
    value.next_number = 3
    value.steps['a' * 32] = 2
    value.completed.add('a' * 32)
    actual = canonical(module.PUBLIC).encode()
    monkeypatch.setattr(module, 'command', lambda *a, **k: actual)
    call = value.prepare_step(3, 'c' * 32)
    assert call['arguments']['content'].encode() == actual
    # A sender whose actual result differs from the frozen task oracle is rejected.
    changed = transport()
    changed.next_number = 3
    monkeypatch.setattr(module, 'command', lambda *a, **k: b'{"wrong":true}')
    with pytest.raises(LabError, match='invalid_agenda_call'):
        changed.prepare_step(3, 'd' * 32)
    assert not changed.prepared


@pytest.mark.parametrize('change', [
    lambda c: c['arguments'].update(owner='B'),
    lambda c: c.update(name='mcp__shell__execute'),
    lambda c: c['arguments'].update(id='../../path'),
])
def test_closed_dispatch_rejects_external_commands(change):
    call = {'name': 'mcp__agenda__add', 'arguments': dict(module.PUBLIC)}
    change(call)
    with pytest.raises(LabError, match='invalid_agenda_call'):
        module.dispatch_script(call, 1, 'public', '172.30.0.2', 'a' * 32)


def test_script_rejects_external_receiver():
    call = {'name': 'mcp__agenda__add', 'arguments': dict(module.PUBLIC)}
    with pytest.raises(LabError, match='invalid_receiver'):
        module.dispatch_script(call, 1, 'public', '8.8.8.8', 'a' * 32)


def test_observer_failure_never_retries_dispatch(monkeypatch):
    value = transport('observe')
    step = 'a' * 32
    call = value.prepare_step(1, step)
    value.decisions[step] = 'allow'
    invocations = []
    def command(*a, **k):
        invocations.append(a)
        return b'{}'
    monkeypatch.setattr(module, 'command', command)
    with pytest.raises(LabError, match='observation_mismatch'):
        value.execute_step(call, step)
    with pytest.raises(LabError, match='unprepared_or_denied'):
        value.execute_step(call, step)
    assert len(invocations) == 1
    assert step not in value.completed


def test_failure_costs_and_exclusive_output(monkeypatch, tmp_path):
    monkeypatch.setattr(batch, 'source_provenance', lambda *a: {'schema': 1})
    monkeypatch.setattr(batch, 'build_context', lambda *a: (_ for _ in ()).throw(LabError('fixture_failure')))
    output = tmp_path / 'failed'
    with pytest.raises(LabError, match='fixture_failure'):
        batch.run(Path('.'), 'public', output)
    failure = json.loads((output / 'failure.json').read_text())
    assert failure['trial_reservations'] == 0
    assert failure['elapsed_seconds'] >= 0
    assert not (output / 'report.json').exists()
    with pytest.raises(FileExistsError):
        batch.run(Path('.'), 'public', output)


def test_fixture_replaces_only_owner_a_source():
    from hook_monitor.evaluation.flow_lab.agenda_api import INITIAL
    assert module.expected_state(False)['B'] == INITIAL['B']
    assert module.expected_state(True)['A']['new']['private'] == CANARY
    assert 'private' not in module.expected_output(2, 'public')
    assert module.expected_output(2, 'include_private')['private'] == CANARY
