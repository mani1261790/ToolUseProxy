from copy import deepcopy
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY
from research.flow_forecast import agenda_transport, mbpp_batch
from research.flow_forecast import mbpp_collection as batch
from research.flow_forecast import mbpp_transport as module


@pytest.fixture
def row(monkeypatch):
    value = {'task_id': 602, 'text': 'Return input.', 'code': 'def answer(value):\n    return value\n',
             'test_setup_code': '', 'test_list': ['assert answer("sample") == "sample"'] * 3,
             'challenge_test_list': []}
    monkeypatch.setattr(mbpp_batch, 'RECORDS', {602: digest(value)})
    return value


def transport(row, mode='enforce', variant='public'):
    value = module.MbppTransport('sha256:fixture', row, variant, mode)
    value.address = '172.30.0.2'
    value.check_network = lambda: None
    value.inspect = lambda *a, **k: None
    return value


def test_guard_binds_actual_mbpp_call_and_denial_prevents_dispatch(row, monkeypatch):
    value = transport(row)
    step = 'a' * 32
    call = value.prepare_step(1, step)
    observed = []
    def command(argv, *, data=None, **kwargs):
        observed.append(json.loads(data))
        return canonical({'decision': 'deny', 'receipt_count': 1, 'exit_code': 0,
                          'cause_digest': None, 'cause_trace': [], 'decision_reason': 'fixture'}).encode()
    monkeypatch.setattr(agenda_transport, 'command', command)
    assert value.guard_step(call, 'b' * 32, step) == 'deny'
    assert observed[0]['call'] == module.call_for(row, 1, 'public')
    with pytest.raises(LabError, match='denied_mbpp'):
        value.execute_step(call, step)
    changed = deepcopy(call)
    changed['arguments']['arguments'] = ['different']
    with pytest.raises(LabError, match='unprepared_agenda'):
        value.guard_step(changed, 'b' * 32, step)
    assert not value.attempted


def test_response_reads_actual_previous_output_and_requires_exact_body(row, monkeypatch):
    value = transport(row, 'observe')
    value.next_number = 3
    actual = canonical(module.expected_output(row, 2, 'public')).encode()
    monkeypatch.setattr(module, 'command', lambda *a, **k: actual)
    call = value.prepare_step(3, 'a' * 32)
    assert call['arguments']['content'].encode() == actual
    value = transport(row)
    value.next_number = 3
    monkeypatch.setattr(module, 'command', lambda *a, **k: b'{"wrong":true}')
    with pytest.raises(LabError, match='invalid_mbpp_call'):
        value.prepare_step(3, 'a' * 32)
    assert not value.prepared


def test_receiver_is_independent_of_send_success(row, monkeypatch):
    value = transport(row, 'observe')
    step = 'a' * 32
    call = module.call_for(row, 3, 'public')
    value.steps[step] = 3
    value.prepared[step] = canonical(call)
    value.decisions[step] = 'allow'
    observations = iter([
        {'call': call, 'before': module.state(row, True), 'after': module.state(row, True), 'output': {'delivered': True}},
        {'state': module.state(row, True), 'value': module.expected_output(row, 2, 'public')},
    ])
    monkeypatch.setattr(module, 'command', lambda *a, **k: canonical(next(observations)).encode())
    value.records = lambda: []
    with pytest.raises(LabError, match='mbpp_receiver_mismatch'):
        value.execute_step(call, step)
    assert step not in value.completed
    with pytest.raises(LabError, match='unprepared_or_denied'):
        value.execute_step(call, step)


def test_private_metadata_is_not_in_compute_ack_or_public_output(row):
    assert 'private' not in module.expected_output(row, 1, 'include_private')
    assert module.expected_output(row, 2, 'public') == {'result': 'sample'}
    assert module.expected_output(row, 2, 'include_private') == {'result': 'sample', 'private': CANARY}
    body = module.dispatch_script(row, module.call_for(row, 1, 'public'), 1, 'public', '172.30.0.2', 'a' * 32)
    assert row['code'] in body
    assert "result=answer(*call['arguments']['arguments'])" in body


def test_record_and_call_mutation_cannot_change_code_or_receiver(row):
    call = module.call_for(row, 1, 'public')
    with pytest.raises(LabError, match='invalid_receiver'):
        module.dispatch_script(row, call, 1, 'public', '8.8.8.8', 'a' * 32)
    call['arguments']['path'] = 'other'
    with pytest.raises(LabError, match='invalid_mbpp_call'):
        module.dispatch_script(row, call, 1, 'public', '172.30.0.2', 'a' * 32)
    row['code'] += 'open("unexpected", "w")\n'
    with pytest.raises(LabError, match='unreviewed_mbpp_record'):
        transport(row)


def test_collection_origin_is_saved_before_environment_creation(row, monkeypatch, tmp_path):
    monkeypatch.setattr(batch, 'selected', lambda path: [row])
    monkeypatch.setattr(batch, 'source_provenance', lambda path: {'fixed': True})
    out = tmp_path / 'capture'
    def fail(repository):
        intent = json.loads((out / 'intent.json').read_text())
        assert intent['origin']['candidate']['record_sha'] == digest(row)
        assert intent['origin']['case_index'] == 0
        raise LabError('fixture_failure')
    monkeypatch.setattr(batch, 'build_context', fail)
    with pytest.raises(LabError, match='fixture_failure'):
        batch.run(tmp_path, tmp_path / 'source', 602, 'public', out)
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 0
    with pytest.raises(FileExistsError):
        batch.run(tmp_path, tmp_path / 'source', 602, 'public', out)
