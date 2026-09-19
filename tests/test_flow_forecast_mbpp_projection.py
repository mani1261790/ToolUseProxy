import ast
from copy import deepcopy
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import mbpp_batch, mbpp_projection as projection, mbpp_projection_batch as batch


@pytest.fixture
def reference(monkeypatch):
    row = {'task_id': 602, 'text': 'Return input.', 'code': 'def answer(value):\n    return value\n',
           'test_setup_code': '', 'test_list': ['assert answer("sample") == "sample"',
                                              'assert answer("other") == "other"', 'assert answer("third") == "third"'],
           'challenge_test_list': []}
    monkeypatch.setattr(mbpp_batch, 'RECORDS', {602: digest(row)})
    return row


def test_interventions_change_only_the_declared_input_or_private_field(reference):
    base, private, inputs = projection.cases(reference)
    assert base['calls'] == private['calls']
    assert base['outputs'][1] == private['outputs'][1]
    assert base['outputs'][2]['private'] != private['outputs'][2]['private']
    assert base['private'] == inputs['private']
    assert base['outputs'][1] != inputs['outputs'][1]
    for case in (base, private, inputs):
        ast.parse(projection.script(reference, case))
        result = projection.verify(reference, case, canonical(projection.expected(case)).encode())
        assert result['calls_observed'] == 3 and result['oracle_matched']
    expected = projection.expected(base)
    expected['final']['result'] = 'changed'
    assert base['final_state']['result'] == 'sample'


def test_unknown_cases_and_mutated_source_fail_closed(reference, monkeypatch):
    case = deepcopy(projection.cases(reference)[0])
    case['private'] = 'arbitrary'
    with pytest.raises(LabError, match='unknown_mbpp_projection_case'):
        projection.script(reference, case)
    monkeypatch.setattr(projection, 'TRANSPORT_SHA', '0' * 64)
    with pytest.raises(LabError, match='source_changed'):
        projection.script(reference, projection.cases(reference)[0])


def test_inconsistent_output_and_duplicate_keys_rejected(reference):
    case = projection.cases(reference)[0]
    expected = projection.expected(case)
    expected['steps'][1]['output']['result'] = 'wrong'
    with pytest.raises(LabError, match='oracle_mismatch'):
        projection.verify(reference, case, canonical(expected).encode())
    with pytest.raises(LabError, match='oracle_mismatch'):
        projection.verify(reference, case, b'{"initial":0,"initial":1}')


def test_failed_observation_is_saved_and_all_attempted_calls_charged(reference, monkeypatch, tmp_path):
    monkeypatch.setattr(batch, 'source_records', lambda path: [reference])
    monkeypatch.setattr(batch, 'source_provenance', lambda path: {'fixed': True})
    monkeypatch.setattr(batch, 'build_context', lambda repository: b'context')
    monkeypatch.setattr(batch, 'build_image', lambda repository, context: 'image')
    monkeypatch.setattr(batch, 'check_isolation', lambda image: None)
    out = tmp_path / 'batch'
    def execute(*args, **kwargs):
        assert (out / 'reservation-3.json').exists()
        assert not (out / 'reservation-4.json').exists()
        return b'{"wrong":true}'
    monkeypatch.setattr(batch, 'execute', execute)
    with pytest.raises(LabError, match='oracle_mismatch'):
        batch.run(tmp_path, tmp_path / 'source', 602, out)
    assert (out / 'observation-1.json').read_bytes() == b'{"wrong":true}'
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 3
    assert not (out / 'report.json').exists()
