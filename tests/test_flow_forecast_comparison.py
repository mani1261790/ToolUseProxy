from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.comparison import CaseScore, operating_point, paired_improvement


def test_comparisons_pair_identical_rows_before_averaging_root_groups():
    candidate = (CaseScore('a1', 'a', .5, True, .9, .8), CaseScore('a2', 'a', .5, False, .1, .8),
                 CaseScore('b1', 'b', 1, True, .8, .7))
    baseline = tuple(replace(row, predicted=.5, edge_f1=.5) for row in candidate)
    brier = paired_improvement(candidate, baseline)
    assert brier['mean'] == pytest.approx((.24 + .21)/2)
    assert brier['roots'] == 2
    assert brier['paired_rows'] == 3
    assert brier['lower'] > 0
    assert paired_improvement(candidate, baseline, metric='edge_f1')['mean'] == pytest.approx(.25)
    # A duplicated variant adds no independent root and does not increase its weight.
    more = candidate + (replace(candidate[0], row_id='a3'), replace(candidate[1], row_id='a4'))
    more_baseline = baseline + (replace(baseline[0], row_id='a3'), replace(baseline[1], row_id='a4'))
    assert paired_improvement(more, more_baseline)['mean'] == brier['mean']


def test_unmatched_or_abstained_rows_are_exposed_not_compared_to_other_cases():
    row = CaseScore('one', 'root', 1, True, .5, None)
    result = paired_improvement((row,), (replace(row, predicted=None),))
    assert result['status'] == 'insufficient_roots'
    assert result['paired_row_coverage'] == 0
    assert paired_improvement((row,), ())['omitted_rows'] == 1
    with pytest.raises(ForecastDataError, match='population_mismatch'):
        paired_improvement((row,), (replace(row, actual=False),))


def test_exact_operating_bounds_count_roots_and_missing_predictions_conservatively():
    normals = {f'normal-{i}': False for i in range(300)}
    positives = {f'positive-{i}': True for i in range(100)}
    result = operating_point(normals, positives)
    assert result['fpr_upper_95'] < .01
    assert result['recall_lower_95'] > .96
    normals['unknown-normal'] = None
    positives['unknown-positive'] = None
    result = operating_point(normals, positives)
    assert result['normal_roots'] == 300 and result['unknown_normal_roots'] == 1
    assert result['positive_roots'] == 101 and result['recalled_roots'] == 100
    assert result['recall'] < 1
    empty = operating_point({}, {})
    assert empty['fpr_upper_95'] is None and empty['recall_lower_95'] is None
