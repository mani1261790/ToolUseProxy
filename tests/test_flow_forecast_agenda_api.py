from copy import deepcopy
import json

import pytest

from hook_monitor.evaluation.flow_lab.agenda_api import AgendaAPI, INITIAL
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast.agenda_cases import cases
from research.flow_forecast.agenda_batch import verify


@pytest.mark.parametrize('case', cases(), ids=lambda c: c['name'])
def test_actual_dispatch_state_and_separate_declared_answers(case):
    service = AgendaAPI(case['principal'])
    initial, rows = service.snapshot(), []
    for call in case['calls']:
        before = service.snapshot()
        reply = service.call(call['name'], call['arguments'])
        rows.append({'call': call, 'output': reply, 'before': before, 'after': service.snapshot()})
    raw = json.dumps({'initial': initial, 'steps': rows, 'final': service.snapshot()}).encode()
    assert verify(case, raw)['oracle_matched']
    rows[0]['after']['B']['shared']['private'] = 'changed-other-owner'
    with pytest.raises(LabError, match='agenda_oracle_mismatch'):
        verify(case, json.dumps({'initial': initial, 'steps': rows, 'final': service.snapshot()}).encode())


def test_reply_and_observer_snapshot_are_detached():
    service = AgendaAPI('A')
    reply = service.call('agenda.get', {'id': 'shared'})
    reply['title'] = 'corrupted'
    snapshot = service.snapshot()
    snapshot['B'].clear()
    assert service.snapshot() == INITIAL
    public = service.call('agenda.public', {'id': 'shared'})
    assert set(public) == {'id', 'title', 'time'}


@pytest.mark.parametrize('arguments', [None, [], {'id': '../shared'}, {'id': 'shared', 'owner': 'B'},
                                      {'id': True}, {'id': 'x' * 129}])
def test_invalid_request_is_atomic(arguments):
    service = AgendaAPI('A')
    before = deepcopy(service.snapshot())
    assert service.call('agenda.get', arguments) == {'error': 'invalid_request'}
    assert before == service.snapshot()


def test_capacity_rejection_does_not_mutate():
    service = AgendaAPI('A')
    for index in range(15):
        assert service.call('agenda.add', {'id': f'id-{index}', 'title': 'Review',
                                           'time': '2026-09-19T10:00'})['created']
    before = service.snapshot()
    assert service.call('agenda.add', {'id': 'overflow', 'title': 'Review',
                                      'time': '2026-09-19T10:00'}) == {'error': 'capacity'}
    assert service.snapshot() == before


def test_failed_execution_keeps_precharged_calls_and_no_success_report(monkeypatch, tmp_path):
    from research.flow_forecast import agenda_batch as batch
    monkeypatch.setattr(batch, 'source_provenance', lambda _: {'revision': 'fixture'})
    monkeypatch.setattr(batch, 'build_context', lambda _: b'fixture')
    monkeypatch.setattr(batch, 'build_image', lambda *a, **k: 'fixture-image')
    monkeypatch.setattr(batch, 'check_isolation', lambda _: None)
    def fail(*args, **kwargs):
        assert len(list((tmp_path / 'batch').glob('reservation-*.json'))) == 3
        raise LabError('simulated_crash')
    monkeypatch.setattr(batch, 'execute', fail)
    with pytest.raises(LabError, match='simulated_crash'):
        batch.run(tmp_path, tmp_path / 'batch')
    assert (tmp_path / 'batch' / 'container-1.json').is_file()
    assert not (tmp_path / 'batch' / 'report.json').exists()
    with pytest.raises(FileExistsError):
        batch.run(tmp_path, tmp_path / 'batch')


def test_external_case_or_code_cannot_be_executed():
    from research.flow_forecast.agenda_batch import script
    case = deepcopy(cases()[0])
    case['calls'][0]['name'] = 'arbitrary-code'
    with pytest.raises(LabError, match='unknown_agenda_case'):
        script(case)
