import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_forecast.protocol import load_protocol
from research.flow_forecast.acceptance import CONDITIONS, RULES, assess


def passing_arithmetic_fixture():
    # Numerical unit-test fixture, not experimental evidence or an adoption report.
    protocol = load_protocol()
    metrics = {name: protocol[key] + (.001 if comparison == 'gt' else 0)
               for name, key, comparison, _ in RULES}
    return metrics, dict.fromkeys(CONDITIONS, True)


def test_every_frozen_numeric_gate_is_required_and_no_result_authorizes_activation():
    metrics, conditions = passing_arithmetic_fixture()
    assert assess(metrics, conditions)['status'] == 'criteria_met_research_only'
    assert assess(metrics, conditions)['product_activation_authorized'] is False
    for key in metrics:
        absent = {k: v for k, v in metrics.items() if k != key}
        result = assess(absent, conditions)
        assert result['status'] == 'inconclusive_do_not_adopt'
        assert key in result['missing_or_insufficient']


def test_good_point_estimates_do_not_replace_sample_sizes_or_confidence_bounds():
    metrics, conditions = passing_arithmetic_fixture()
    metrics['test_normal_roots'] = 2
    metrics['fpr_upper'] = .7
    result = assess(metrics, conditions)
    assert result['status'] == 'inconclusive_do_not_adopt'
    assert 'test_normal_roots' in result['missing_or_insufficient']
    assert 'fpr_upper' in result['performance_failures']
    metrics['test_normal_roots'] = 300
    assert assess(metrics, conditions)['status'] == 'does_not_meet_criteria'


def test_missing_cross_model_or_ablation_evidence_is_not_assumed_success():
    metrics, conditions = passing_arithmetic_fixture()
    for key in CONDITIONS:
        result = assess(metrics, {k: v for k, v in conditions.items() if k != key})
        assert result['status'] == 'inconclusive_do_not_adopt'
    conditions['parent_relation_ablation_benefit'] = False
    assert assess(metrics, conditions)['status'] == 'does_not_meet_criteria'


@pytest.mark.parametrize('value', [float('nan'), float('inf'), True, '1'])
def test_invalid_numeric_evidence_is_rejected(value):
    metrics, conditions = passing_arithmetic_fixture()
    metrics['fpr_upper'] = value
    with pytest.raises(ForecastDataError):
        assess(metrics, conditions)


@pytest.mark.parametrize('key,value', [('test_normal_roots', 300.5), ('model_bytes', -1),
                                      ('fpr_upper', -.1), ('truth_coverage', 2)])
def test_impossible_values_cannot_pass_thresholds(key, value):
    metrics, conditions = passing_arithmetic_fixture()
    metrics[key] = value
    with pytest.raises(ForecastDataError, match='out_of_domain'):
        assess(metrics, conditions)
