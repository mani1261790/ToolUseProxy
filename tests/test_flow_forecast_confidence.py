import pytest

from hook_monitor.evaluation.flow_forecast.confidence import (
    binomial_upper, paired_root_interval, select_threshold, zero_failure_sample_size,
)
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_forecast.protocol import load_protocol


def test_exact_bounds_match_known_binomial_examples():
    assert binomial_upper(0, 300) == pytest.approx(1 - .05 ** (1/300))
    assert binomial_upper(0, 300) < .01
    assert binomial_upper(0, 20) > .1  # few safe observations cannot certify a 1% rate
    assert binomial_upper(4, 20) == pytest.approx(.401029, abs=1e-6)  # NIST 95% one-sided upper
    assert binomial_upper(20, 20) == 1
    assert binomial_upper(0, 0) is None
    assert zero_failure_sample_size(.01) == 299
    assert zero_failure_sample_size(.05) == 59


def test_bootstrap_is_root_based_reproducible_and_rejects_small_evidence():
    assert paired_root_interval({'a': .1})['status'] == 'insufficient_roots'
    first = paired_root_interval({'a': .1, 'b': .2, 'c': -.1}, draws=100)
    assert first == paired_root_interval({'c': -.1, 'b': .2, 'a': .1}, draws=100)
    assert first['mean'] == pytest.approx(.2/3)
    assert first['lower'] <= first['mean'] <= first['upper']


def test_calibration_threshold_counts_groups_not_duplicate_branches():
    roots = {'a': (.3,) * 100, 'b': (.6,)}
    result = select_threshold(roots, maximum_fpr=0)
    assert result['normal_roots'] == 2
    assert result['threshold'] > .6
    assert result['false_alarm_roots'] == 0
    assert result['upper_95'] > .5
    assert select_threshold({'a': (1.0,)}, maximum_fpr=0)['status'] == 'no_finite_operating_point'
    assert select_threshold({'a': (None,)})['status'] == 'insufficient_calibration'


def test_protocol_is_pinned_and_cannot_be_silently_relaxed(tmp_path):
    protocol = load_protocol()
    assert protocol['minimum_test_normal_roots'] == 300
    assert protocol['automatic_batch_extension'] is False
    path = tmp_path / 'changed.json'
    path.write_text('{}')
    with pytest.raises(ForecastDataError, match='frozen_protocol_changed'):
        load_protocol(path)
