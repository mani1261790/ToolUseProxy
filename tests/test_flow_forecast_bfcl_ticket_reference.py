import hashlib
import json
from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import bfcl_ticket_reference as module


@pytest.fixture
def lab(tmp_path, monkeypatch):
    source = tmp_path / 'ticket.py'
    source.write_text('# synthetic source; never executed on host\n')
    monkeypatch.setattr(module, 'source_provenance', lambda root: {'fixture': 'same code'})
    monkeypatch.setattr(module, 'SOURCE_SHA', hashlib.sha256(source.read_bytes()).hexdigest())
    monkeypatch.setattr(module, 'build_context', lambda *a: b'fixture context')
    monkeypatch.setattr(module, 'build_image', lambda *a, **k: 'fixture image')
    monkeypatch.setattr(module, 'check_isolation', lambda *a: None)
    return source


def test_reservations_precede_execution_and_oracles_cover_reply_and_state(lab, tmp_path, monkeypatch):
    out = tmp_path / 'batch'
    count = 0
    def execute(image, program, *, name):
        nonlocal count
        count += 1
        reservation = json.loads((out / f'reservation-{count}.json').read_text())
        assert reservation['trial_charges'] == 2
        assert reservation['container'] == name
        assert reservation['script_sha'] == hashlib.sha256(program.encode()).hexdigest()
        return canonical(module.cases()[count - 1]['expected']).encode()
    monkeypatch.setattr(module, 'execute', execute)
    report = module.run(tmp_path, lab, out)
    assert count == 6 and report['trial_charges'] == 12
    assert report['all_oracles_matched']
    assert report['accepted_independent_groups'] == report['new_model_calls'] == 0
    with pytest.raises(FileExistsError):
        module.run(tmp_path, lab, out)


def test_changed_source_and_arbitrary_call_rejected_before_execution(lab, tmp_path):
    case = deepcopy(module.cases()[0])
    case['call'] = 'arbitrary()'
    with pytest.raises(LabError, match='unreviewed'):
        module.script(lab.read_text(), case)
    lab.write_text('changed')
    with pytest.raises(LabError, match='digest_mismatch'):
        module.run(tmp_path, lab, tmp_path / 'batch')
    assert not (tmp_path / 'batch').exists()


def test_reply_success_does_not_hide_wrong_post_state():
    case = module.cases()[3]
    observed = deepcopy(case['expected'])
    observed['state'] = case['initial']
    assert not module.verify(case, canonical(observed).encode())['oracle_matched']


def test_failure_retains_charge_and_does_not_retry(lab, tmp_path, monkeypatch):
    out = tmp_path / 'batch'
    def fail(*args, **kwargs):
        raise LabError('fixture_failure')
    monkeypatch.setattr(module, 'execute', fail)
    with pytest.raises(LabError, match='fixture_failure'):
        module.run(tmp_path, lab, out)
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 2
    assert not (out / 'reservation-2.json').exists()
    assert not (out / 'report.json').exists()


def test_expired_budget_does_not_dispatch(lab, tmp_path, monkeypatch):
    times = iter([0, 181, 181])
    monkeypatch.setattr(module, 'execute', lambda *a, **k: pytest.fail('executed after deadline'))
    with pytest.raises(LabError, match='budget_exhausted'):
        module.run(tmp_path, lab, tmp_path / 'batch', clock=lambda: next(times))
    assert json.loads((tmp_path / 'batch/failure.json').read_text())['trial_reservations'] == 0


def test_repository_mismatch_rejected_before_output(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(module, 'source_provenance', lambda root: {'root': str(root)})
    with pytest.raises(LabError, match='repository_implementation_mismatch'):
        module.run(tmp_path, lab, tmp_path / 'batch')
    assert not (tmp_path / 'batch').exists()


def test_failed_reservation_write_does_not_charge_or_execute(lab, tmp_path, monkeypatch):
    write = module._write_private
    def fail_reservation(path, data):
        if path.name.startswith('reservation-'):
            raise OSError('fixture write failed')
        write(path, data)
    monkeypatch.setattr(module, '_write_private', fail_reservation)
    monkeypatch.setattr(module, 'execute', lambda *a, **k: pytest.fail('unreserved execution'))
    out = tmp_path / 'batch'
    with pytest.raises(OSError, match='fixture write failed'):
        module.run(tmp_path, lab, out)
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 0
