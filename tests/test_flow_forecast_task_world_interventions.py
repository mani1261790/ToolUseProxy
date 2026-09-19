from copy import deepcopy
import subprocess
import sys

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import task_world_interventions as module
from research.flow_forecast.task_worlds import encoded


@pytest.mark.parametrize('name', ['inventory', 'calendar', 'ledger'])
def test_changed_inputs_produce_independently_declared_answers(name):
    cases = module.cases(name)
    for case in cases:
        actual = subprocess.check_output([sys.executable, '-I', '-S', '-B', '-c', module.script(name, case)])
        assert actual == encoded(case['answer'])
    assert all(case['answer'] != cases[0]['answer'] for case in cases[1:])
    changed = deepcopy(cases[0])
    changed['input']['unexpected'] = True
    with pytest.raises(LabError):
        module.script(name, changed)


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(module, 'build_context', lambda _: b'fixture')
    monkeypatch.setattr(module, 'build_image', lambda *a, **k: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(module, 'check_isolation', lambda _: None)
    monkeypatch.setattr(module, 'execute', lambda image, source, **kwargs: subprocess.check_output(
        [sys.executable, '-I', '-S', '-B', '-c', source]))


def test_batch_reserves_before_execution_and_never_claims_independence(lab, monkeypatch, tmp_path):
    output = tmp_path / 'batch'
    original = module.execute
    def inspected(image, source, **kwargs):
        number = len(list(output.glob('result-*.json'))) + 1
        assert (output / f'reservation-{number}.json').exists()
        assert (output / f'container-{number}.json').exists()
        return original(image, source, **kwargs)
    monkeypatch.setattr(module, 'execute', inspected)
    report = module.run(tmp_path, 'calendar', output)
    assert report['trial_charges'] == 3 and report['independent_new_tasks_accepted'] == 0
    assert report['semantic_truth_promoted'] is False
    assert [r['changed_from_baseline'] for r in report['results']] == [False, True, True]
    with pytest.raises(FileExistsError):
        module.run(tmp_path, 'calendar', output)


def test_failure_keeps_charge_and_no_completion(lab, monkeypatch, tmp_path):
    monkeypatch.setattr(module, 'execute', lambda *a, **k: b'wrong')
    output = tmp_path / 'batch'
    with pytest.raises(LabError, match='answer_mismatch'):
        module.run(tmp_path, 'ledger', output)
    assert (output / 'reservation-1.json').exists()
    assert not (output / 'report.json').exists()


def test_unsafe_profile_never_starts_and_cleans_only_owned_container(monkeypatch):
    calls = []
    monkeypatch.setattr(module, 'command', lambda argv, **kwargs: calls.append(argv) or b'')
    monkeypatch.setattr(module, 'document', lambda argv: [{'HostConfig': {'SecurityOpt': []}, 'Config': {'Labels': {}}}])
    name = 'tup-lab-' + 'b' * 32
    with pytest.raises(LabError, match='unsafe_container_profile'):
        module.execute('sha256:' + 'a' * 64, 'unused', name=name)
    assert not any('start' in call for call in calls)
    assert calls[-1] == ['docker', 'rm', '--force', name]


def test_create_timeout_still_attempts_owned_cleanup(monkeypatch):
    calls = []
    def failed(argv, **kwargs):
        calls.append(argv)
        if argv[1] == 'create':
            raise LabError('command_timeout')
        return b''
    monkeypatch.setattr(module, 'command', failed)
    name = 'tup-lab-' + 'c' * 32
    with pytest.raises(LabError, match='command_timeout'):
        module.execute('sha256:' + 'a' * 64, 'unused', name=name)
    assert calls[-1] == ['docker', 'rm', '--force', name]
