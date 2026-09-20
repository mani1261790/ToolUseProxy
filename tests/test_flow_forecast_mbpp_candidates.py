from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.mbpp_candidates import inspect_task, inventory


def task():
    return {'task_id': 700, 'text': 'Return the first value.',
            'code': 'def first(values):\n    return values[0]\n',
            'test_setup_code': '', 'test_list': ['assert first([4, 8]) == 4'],
            'challenge_test_list': []}


def test_literal_cases_are_candidates_without_execution_or_independence_claim():
    row = inspect_task(task())
    assert row['cases'] == [{'arguments': [[4, 8]], 'expected': 4}]
    assert row['status'] == 'candidate'
    assert row['execution_verified'] is False
    assert row['challenge_tests_checked'] is False


def test_arbitrary_reference_body_is_never_executed(tmp_path):
    value = task()
    target = tmp_path / 'must-not-exist'
    value['code'] = f'def first(values):\n    open({str(target)!r}, "w").write("bad")\n    return values[0]\n'
    # Inventory is not a security allowlist. Even this candidate cannot run.
    assert inspect_task(value)['status'] == 'candidate'
    assert not target.exists()


@pytest.mark.parametrize('source,reason', [
    ('assert first(list(range(2))) == 0', 'nonliteral_test_values'),
    ('assert first(values=[1]) == 1', 'unsupported_test_call'),
    ('assert first([1]) != 2', 'not_literal_equality_test'),
    ('assert first([1]) == (1, 2)', 'non_json_test_values'),
    ('assert first([1]) == 1.0', 'non_json_test_values'),
    ('assert first([1]) == 1\nopen("anything", "w")', 'not_literal_equality_test'),
])
def test_nonliteral_and_non_json_tests_remain_unsupported(source, reason):
    value = task()
    value['test_list'] = [source]
    assert inspect_task(value)['reason'] == reason


def test_heldout_rows_cannot_enter_development_inventory():
    value = task()
    value['task_id'] = 11
    with pytest.raises(ForecastDataError, match='invalid_mbpp_training_task'):
        inspect_task(value)


def test_source_mutation_rejected_before_json_or_python_processing(tmp_path):
    source = tmp_path / 'source.jsonl'
    source.write_text('malformed and untrusted')
    with pytest.raises(ForecastDataError, match='mbpp_source_digest_mismatch'):
        inventory(source)


def test_case_and_reference_changes_change_evidence_hashes():
    original = task()
    changed = deepcopy(original)
    changed['test_list'][0] = 'assert first([5]) == 5'
    assert inspect_task(original)['record_sha'] != inspect_task(changed)['record_sha']
    changed['code'] += '# changed reference bytes\n'
    assert inspect_task(original)['reference_sha'] != inspect_task(changed)['reference_sha']
