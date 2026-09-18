from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.experiment import build_models, evaluate, freeze_plan
from test_flow_forecast_baselines import dataset
from test_flow_forecast_evaluate import partition_copy


def test_empty_holdout_cannot_be_substituted_with_training_results():
    data = dataset()
    models, costs = build_models(data)
    plan = freeze_plan(data, models)
    report = evaluate(data, models, plan)
    assert report['selected_probability_baseline'] is None
    assert report['scope'] == 'heldout_comparison'
    for conditions in report['models'].values():
        for result in conditions.values():
            assert result['probability']['row_count'] == 0
            assert result['operating_points']['0.01']['fpr_upper_95'] is None
    assert all(value >= 0 for value in costs.values())
    smoke = evaluate(data, models, plan, partition='train')
    assert smoke['scope'] == 'training_smoke_only'
    strata = smoke['models']['sequence']['observe/4']['strata']
    assert {'task/plain_http', 'task/base64_http', 'tool/http', 'tool/file'} <= set(strata)
    assert strata['tool/http']['probability']['row_count'] < smoke['models']['sequence']['observe/4']['probability']['row_count']
    assert smoke['models']['sequence']['observe/4']['probability']['root_count'] == 2
    assert smoke['product_activation_authorized'] is False
    assert smoke['models']['sequence']['observe/4']['operating_points']['0.01']['recall_lower_95'] is None


def test_calibration_is_fixed_before_test_comparison_and_edited_plans_are_rejected():
    train = dataset()
    calibration = assemble(train.branches + partition_copy(train, 'calibration'))
    heldout = assemble(calibration.branches + partition_copy(train, 'test'))
    first_models, _ = build_models(calibration)
    second_models, _ = build_models(heldout)
    first, second = freeze_plan(calibration, first_models), freeze_plan(heldout, second_models)
    assert first['models'] == second['models']
    assert first['selected_probability_baseline'] == second['selected_probability_baseline']
    report = evaluate(heldout, second_models, second)
    comparison = report['paired_comparisons']['observe/4']['frequency']['brier']
    assert comparison['roots'] == 2
    assert comparison['paired_rows'] == 24
    edited = deepcopy(second)
    edited['models']['sequence']['conditions']['observe/4']['thresholds']['0.01']['threshold'] = .123
    with pytest.raises(ForecastDataError, match='comparison_plan_mismatch'):
        evaluate(heldout, second_models, edited)


def test_incomplete_comparison_and_budget_exhaustion_fail_explicitly():
    data = dataset()
    with pytest.raises(ForecastDataError, match='incomplete_model_comparison'):
        freeze_plan(data, {})
    def stop():
        raise ForecastDataError('research_time_budget_exceeded')
    with pytest.raises(ForecastDataError, match='research_time_budget_exceeded'):
        build_models(data, check_budget=stop)


def test_cli_reports_insufficient_evidence_and_never_overwrites_results(tmp_path):
    import json
    from hook_monitor.evaluation.flow_forecast.dataset import write_dataset
    from research.flow_forecast.compare import main
    source = tmp_path / 'data'
    write_dataset(dataset(), source)
    plan, report = tmp_path / 'plan.json', tmp_path / 'report.json'
    main(['prepare', '--dataset', str(source), '--output', str(plan)])
    main(['evaluate', '--dataset', str(source), '--plan', str(plan), '--output', str(report)])
    result = json.loads(report.read_text())
    assert result['acceptance']['status'] == 'inconclusive_do_not_adopt'
    assert result['acceptance_metrics']['test_normal_roots'] == 0
    assert result['generalization']['agent_models']['evaluated'] is False
    assert 'unused_test_partition' in result['acceptance']['missing_or_insufficient']
    original = report.read_bytes()
    with pytest.raises(SystemExit):
        main(['evaluate', '--dataset', str(source), '--plan', str(plan), '--output', str(report)])
    assert report.read_bytes() == original
