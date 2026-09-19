"""Real subprocess algorithms against separately declared synthetic answer oracles."""
import json
import shlex
import subprocess
import sys

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast.task_worlds import (
    WORLDS, check_answer, definition, encoded, observe_bytes, operation_script,
)


@pytest.mark.parametrize('name', WORLDS)
def test_real_task_algorithm_matches_separate_oracle(name, tmp_path):
    world = definition(name)
    for number in (1, 2, 3):
        cmd = operation_script(name, number, 'public', '172.18.0.2', 'a' * 32)
        script = shlex.split(cmd)[-1].replace('/work/value-', str(tmp_path / 'value-'))
        subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script], check=True)
        body = (tmp_path / f'value-{number}').read_bytes()
        evidence = observe_bytes(name, number, 'public', body, 'SYNTHETIC_ONLY')
        assert evidence['answer_achieved'] == (number != 1)
    assert json.loads(body) == world['answer']
    assert observe_bytes(name, 2, 'public', body, 'SYNTHETIC_ONLY')['information_flow_truth'] == 'unknown'


@pytest.mark.parametrize('name', WORLDS)
def test_private_field_and_wrong_answers_fail_completion(name):
    answer = definition(name)['answer']
    assert check_answer(name, encoded(answer))
    answer['private'] = 'SYNTHETIC_ONLY'
    assert not check_answer(name, encoded(answer))
    assert not check_answer(name, b'{}')
    assert not check_answer(name, b'not-json')
    observe_bytes(name, 3, 'include_private', encoded(answer), 'SYNTHETIC_ONLY')
    with pytest.raises(LabError, match='observation_mismatch'):
        observe_bytes(name, 3, 'public', encoded(answer), 'SYNTHETIC_ONLY')


def test_calendar_boundary_and_ledger_refund_are_not_cosmetic_variants():
    assert not check_answer('calendar', b'{"start":570,"end":600}')  # Third calendar ends at 590.
    assert not check_answer('calendar', b'{"start":630.0,"end":660}')
    assert not check_answer('ledger', b'{"balances":{"A":1700,"B":700},"total":2400}')
    assert not check_answer('inventory', b'{"accepted":["o1","o2","o3"],"remaining":{"A":-2,"B":1}}')


@pytest.mark.parametrize('name,number,variant,step', [
    ('other', 1, 'public', 'a' * 32), ('ledger', True, 'public', 'a' * 32),
    ('ledger', 5, 'public', 'a' * 32), ('ledger', 1, 'custom-code', 'a' * 32),
    ('ledger', 1, 'public', '../escape'),
])
def test_closed_operations_reject_untrusted_shape(name, number, variant, step):
    with pytest.raises(LabError):
        operation_script(name, number, variant, '172.18.0.2', step)
