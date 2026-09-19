from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import measured_budget as module


@pytest.fixture
def pilot(monkeypatch):
    # Two captures share one intervention batch. Enforce stopped early, so actual
    # trial charges must not shrink the next capture's full reservation.
    intervention = {'report': {'trial_charges': 3, 'elapsed_seconds': 2,
                              'artifact_bytes_before_report': 100}}
    capture = {'intent': {'root': 'first'}, 'report': {
        'trial_charges': 11, 'elapsed_seconds': 10, 'artifact_bytes_before_report': 200,
        'conditions': [{}, {'termination': 'blocked'}]}}
    def read(path):
        value = deepcopy(capture)
        value['intent']['root'] = path.name
        return None, value
    monkeypatch.setattr(module, 'read_capture', read)
    monkeypatch.setattr(module, 'read_interventions', lambda _: intervention)
    monkeypatch.setattr(module, 'bind_capture', lambda path, _: {
        'capture_report_sha': digest(read(path)[1]['report']),
        'intervention_report_sha': digest(intervention['report'])})
    return [{'capture': 'first', 'interventions': 'shared'},
            {'capture': 'second', 'interventions': 'shared'}]


def test_shared_costs_and_censored_pilot_do_not_underbudget(pilot):
    result = module.budget(pilot)
    observed = result['observed_selected_completed_batches']
    assert observed['trial_charges'] == 25
    assert observed['elapsed_seconds'] == 22
    assert observed['artifact_bytes_before_reports'] == 500
    assert observed['interventions'] == 1
    assert observed['blocked_enforce_captures'] == 2
    plan = result['conditional_collection_plan']
    assert plan['required_independent_roots'] == 520
    assert plan['explicit_batches'] == 1040
    assert plan['trial_reservations'] == 8840
    assert plan['serial_batch_deadline_sum_seconds'] == 187200
    assert plan['estimated_provider_cost'] is None
    assert plan['estimated_end_to_end_seconds'] is None
    assert not observed['includes_failed_or_unlisted_batches']
    assert result['trials_started'] == 0
    assert not result['independence_verified']


def test_duplicate_capture_cannot_inflate_cost_sample(pilot):
    with pytest.raises(ForecastDataError, match='duplicate_budget_capture'):
        module.budget([pilot[0], pilot[0]])


def test_changed_binding_cannot_attach_different_costs(pilot, monkeypatch):
    monkeypatch.setattr(module, 'bind_capture', lambda *_: {
        'capture_report_sha': '0' * 64, 'intervention_report_sha': '0' * 64})
    with pytest.raises(ForecastDataError, match='budget_evidence_changed'):
        module.budget(pilot)


def test_invalid_capture_never_falls_back_to_report_only(pilot, monkeypatch):
    def reject(_):
        raise ForecastDataError('invalid_task_world_evidence')
    monkeypatch.setattr(module, 'read_capture', reject)
    with pytest.raises(ForecastDataError, match='invalid_task_world_evidence'):
        module.budget(pilot)


@pytest.mark.parametrize('pairs', [[], {}, [None], [{'capture': 'x'}],
                                 [{'capture': 1, 'interventions': 'x'}]])
def test_malformed_inputs_fail(pairs):
    with pytest.raises(ForecastDataError, match='invalid_budget_inputs'):
        module.budget(pairs)
