import pytest

from research.flow_forecast.collection_plan import plan


def test_protocol_population_and_controls_are_budgeted():
    result = plan(attempts_per_root=4, controls_per_batch=3, seconds_per_attempt=60)
    assert result['total_independent_roots'] == 520
    assert result['roots_per_batch'] == 4
    assert result['planned_batches'] == 130
    assert result['planned_attempts_including_controls'] == 2470
    assert result['estimated_serial_seconds'] == 148200
    assert result['estimated_provider_cost'] is None
    assert result['trials_started'] == 0
    assert result['independence_verified'] is False


def test_time_budget_limits_capacity_and_strata_do_not_share_batches():
    result = plan(attempts_per_root=4, controls_per_batch=3, seconds_per_attempt=120)
    assert result['roots_per_batch'] == 3
    assert result['planned_batches'] == 175


@pytest.mark.parametrize('overrides', [
    {'attempts_per_root': True}, {'attempts_per_root': 0}, {'attempts_per_root': 21},
    {'controls_per_batch': 20}, {'controls_per_batch': -1},
    {'seconds_per_attempt': float('nan')}, {'seconds_per_attempt': float('inf')},
    {'seconds_per_attempt': 0}, {'seconds_per_attempt': 1000},
])
def test_invalid_or_impossible_batch_is_rejected(overrides):
    args = dict(attempts_per_root=4, controls_per_batch=3, seconds_per_attempt=60)
    args.update(overrides)
    with pytest.raises(ValueError):
        plan(**args)
