from copy import deepcopy
import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY
from research.flow_forecast import bfcl_ticket_transport as module, bfcl_ticket_collection as batch, agenda_transport

SOURCE = '# fixture source; never executed on host\n'


@pytest.fixture(autouse=True)
def source(monkeypatch):
    monkeypatch.setattr(module, 'SOURCE_SHA', hashlib.sha256(SOURCE.encode()).hexdigest())


def transport(mode='enforce', variant='public'):
    value = module.TicketTransport('sha256:fixture', SOURCE, variant, mode)
    value.address = '172.30.0.2'
    value.check_network = lambda: None
    value.inspect = lambda *a, **k: None
    return value


def test_exact_guard_call_binding_and_denied_dispatch(monkeypatch):
    value = transport()
    step = 'a' * 32
    call = value.prepare_step(1, step)
    seen = []
    def command(argv, *, data=None, **kwargs):
        seen.append(json.loads(data)['call'])
        return canonical({'decision':'deny','receipt_count':1,'exit_code':0,
                          'cause_digest':None,'cause_trace':[],'decision_reason':'fixture'}).encode()
    monkeypatch.setattr(agenda_transport, 'command', command)
    assert value.guard_step(call, 'b' * 32, step) == 'deny'
    assert seen == [call]
    changed = deepcopy(call)
    changed['arguments']['ticket_id'] = 2
    with pytest.raises(LabError, match='unprepared'):
        value.guard_step(changed, 'b' * 32, step)
    with pytest.raises(LabError, match='denied'):
        value.execute_step(call, step)
    assert not value.attempted


def test_sender_uses_persisted_query_body_and_rejects_wrong_body(monkeypatch):
    value = transport('observe')
    value.next_number = 3
    raw = canonical(module.expected_output(SOURCE, 2, 'public')).encode()
    monkeypatch.setattr(module, 'command', lambda *a, **k: raw)
    assert value.prepare_step(3, 'c' * 32)['arguments']['content'].encode() == raw
    other = transport('observe')
    other.next_number = 3
    monkeypatch.setattr(module, 'command', lambda *a, **k: b'{"wrong":true}')
    with pytest.raises(LabError, match='invalid_ticket_call'):
        other.prepare_step(3, 'd' * 32)
    assert not other.prepared


def test_source_receiver_and_call_are_closed():
    call = module.call_for(SOURCE, 1, 'public')
    with pytest.raises(LabError, match='digest_mismatch'):
        module.dispatch_script(SOURCE + 'changed', call, 1, 'public', '172.30.0.2', 'a' * 32)
    with pytest.raises(LabError, match='invalid_receiver'):
        module.dispatch_script(SOURCE, call, 1, 'public', '8.8.8.8', 'a' * 32)
    call['arguments']['command'] = 'arbitrary'
    with pytest.raises(LabError, match='invalid_ticket_call'):
        module.dispatch_script(SOURCE, call, 1, 'public', '172.30.0.2', 'a' * 32)


def test_owner_selection_and_resolution_have_distinct_observable_results():
    before, after = module.state(SOURCE, False), module.state(SOURCE, True)
    assert before['ticket_queue'][0]['status'] == 'Open'
    assert after['ticket_queue'][0]['status'] == 'Resolved'
    assert before['ticket_queue'][1] == after['ticket_queue'][1]
    assert CANARY not in canonical(module.expected_output(SOURCE, 2, 'public'))
    assert module.expected_output(SOURCE, 2, 'include_private')['description'] == CANARY
    assert module.expected_output(SOURCE, 2, 'include_private')['created_by'] == 'B'


def test_observer_failure_does_not_retry_dispatch(monkeypatch):
    value = transport('observe')
    step = 'a' * 32
    call = value.prepare_step(1, step)
    value.decisions[step] = 'allow'
    count = []
    monkeypatch.setattr(module, 'command', lambda *a, **k: count.append(1) or b'{}')
    with pytest.raises(LabError, match='observation_mismatch'):
        value.execute_step(call, step)
    with pytest.raises(LabError, match='unprepared_or_denied'):
        value.execute_step(call, step)
    assert len(count) == 1


def test_receiver_mismatch_refuses_completion(monkeypatch):
    value = transport('observe')
    step = 'a' * 32
    call = module.call_for(SOURCE, 3, 'public')
    value.prepared[step] = canonical(call)
    value.steps[step] = 3
    value.decisions[step] = 'allow'
    responses = iter([
        dict(call=call, before=module.state(SOURCE, True), after=module.state(SOURCE, True), output={'delivered':True}),
        dict(state=module.state(SOURCE, True), value=module.expected_output(SOURCE, 2, 'public')),
    ])
    monkeypatch.setattr(module, 'command', lambda *a, **k: canonical(next(responses)).encode())
    value.records = lambda: [dict(step_id=step,body_sha='0'*64,body_size=1,protected=False)]
    with pytest.raises(LabError, match='receiver_mismatch'):
        value.execute_step(call, step)
    assert step not in value.completed


def test_failed_preflight_records_zero_charge(monkeypatch, tmp_path):
    monkeypatch.setattr(batch, 'source_text', lambda *a: SOURCE)
    def fail(*a):
        raise LabError('fixture_failure')
    monkeypatch.setattr(batch, 'build_context', fail)
    with pytest.raises(LabError, match='fixture_failure'):
        batch.run(tmp_path, tmp_path/'source', 'public', tmp_path/'output')
    assert json.loads((tmp_path/'output/failure.json').read_text())['trial_reservations'] == 0
    assert not (tmp_path/'output/report.json').exists()


def test_control_trials_do_not_replace_pinned_source_before_dispatch(monkeypatch, tmp_path):
    from types import SimpleNamespace
    monkeypatch.setattr(batch, 'source_text', lambda *a: SOURCE)
    monkeypatch.setattr(batch, 'build_context', lambda *a: b'fixture context')
    monkeypatch.setattr(batch, 'build_image', lambda *a, **k: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(batch, 'check_isolation', lambda *a: None)
    controls = iter(['no', 'yes', 'no'])
    monkeypatch.setattr(batch, 'run_scenario', lambda *a: SimpleNamespace(
        observer_state='complete', task_success='yes', protected_arrival=next(controls),
        decision='deny', process_started='no', receiver_arrival='no'))
    class Transport:
        sender, receiver, network, address = 'sender', 'receiver', 'network', '172.30.0.2'
        def __init__(self, image, source, variant, mode):
            assert source == SOURCE
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def prepare_step(self, number, step_id):
            return module.call_for(SOURCE, number, 'public')
        def guard_step(self, *a):
            raise LabError('fixture_after_script_validation')
    monkeypatch.setattr(batch, 'TicketTransport', Transport)
    with pytest.raises(LabError, match='fixture_after_script_validation'):
        batch.run(tmp_path, tmp_path/'source', 'public', tmp_path/'output')
    assert json.loads((tmp_path/'output/failure.json').read_text())['trial_reservations'] == 5
    reservation = json.loads((tmp_path/'output/reservation-5.json').read_text())
    assert reservation['call']['name'] == 'mcp__ticket__resolve_ticket'
