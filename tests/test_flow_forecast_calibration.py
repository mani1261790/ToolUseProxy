from dataclasses import replace
import math

import pytest

from hook_monitor.evaluation.flow_forecast.calibration import (
    ProbabilitySample as Sample, probability_scores, reliability_bins,
)
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError


def test_known_two_of_three_branch_probability_has_expected_proper_scores():
    rows = (Sample('root', 2/3, True, 2/3), Sample('root', 2/3, False, 1/3))
    scores = probability_scores(rows)
    assert scores['brier'] == pytest.approx(2/9)
    assert scores['log_loss'] == pytest.approx(-(2/3 * math.log(2/3) + 1/3 * math.log(1/3)))
    bins = reliability_bins(rows)
    assert bins[6]['mean_probability'] == pytest.approx(2/3)
    assert bins[6]['observed_rate'] == pytest.approx(2/3)


def test_unknown_labels_and_abstentions_never_turn_into_negatives():
    rows = (Sample('a', .2, None), Sample('b', None, True), Sample('c', .5, False))
    scores = probability_scores(rows)
    assert scores['brier'] == .25
    assert scores['unknown_label_rows'] == 1
    assert scores['abstained_labeled_rows'] == 1
    assert scores['coverage'] == .5
    assert probability_scores((rows[0],))['brier'] is None
    assert probability_scores((rows[1],))['coverage'] == 0


def test_duplicate_rows_do_not_inflate_one_root_weight():
    first, second = Sample('a', 0, True), Sample('b', 0, False)
    assert probability_scores((first, second))['brier'] == .5
    assert probability_scores((first,) * 100 + (second,))['brier'] == .5
    assert reliability_bins((first,) * 100 + (second,))[0]['observed_rate'] == pytest.approx(.5)


def test_impossible_confident_prediction_keeps_infinite_loss_explicit():
    result = probability_scores((Sample('a', 0, True),))
    assert result['log_loss'] is None and result['log_loss_status'] == 'infinite'
    assert probability_scores(())['log_loss_status'] == 'no_labels'
    assert probability_scores((Sample('a', 1, True),))['log_loss'] == 0
    assert reliability_bins((Sample('a', 1, True),))[-1]['rows'] == 1


@pytest.mark.parametrize('value', [-.01, 1.01, float('nan'), float('inf'), True])
def test_invalid_probabilities_are_rejected(value):
    with pytest.raises(ForecastDataError):
        Sample('a', value, True)


def test_invalid_labels_weights_and_bin_counts_are_rejected():
    row = Sample('a', .5, True)
    for change in ({'actual': 1}, {'weight': 0}, {'weight': float('inf')}, {'weight': 1e308}):
        with pytest.raises(ForecastDataError):
            replace(row, **change)
    with pytest.raises(ForecastDataError):
        reliability_bins((row,), bins=0)
