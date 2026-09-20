from copy import deepcopy
from dataclasses import replace
import json

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble, write_dataset
from hook_monitor.evaluation.flow_forecast.evaluate import evaluate, main, prepare
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from test_flow_forecast_baselines import dataset


def partition_copy(data, partition):
    bounds = {'calibration': (80, 90), 'test': (90, 100)}[partition]
    roots = []
    for index in range(1000):
        root = f'{partition}-root-{index}'
        bucket = int(digest(['split-v1', root])[:16], 16) % 100
        if bounds[0] <= bucket < bounds[1]:
            roots.append(root)
        if len(roots) == 2:
            break
    mapping = dict(zip(sorted({b.prefix.root_case_id for b in data.branches}), roots))
    return tuple(replace(b, prefix=replace(b.prefix, root_case_id=mapping[b.prefix.root_case_id],
                                           environment_version=f'{partition}-environment'),
                         control_group=mapping[b.prefix.root_case_id]) for b in data.branches)


def test_missing_holdout_is_not_replaced_with_training_rows():
    data = dataset()
    plan = prepare(data)
    assert plan['status'] == 'insufficient_calibration'
    assert plan['selected_probability_baseline'] is None
    report = evaluate(data, plan)
    for result in report['models'].values():
        for condition in result['conditions'].values():
            assert condition['status'] == 'insufficient_evaluation_roots'
            assert condition['probability']['row_count'] == 0
    smoke = evaluate(data, plan, partition='train')
    assert smoke['scope'] == 'training_smoke_only'
    assert smoke['models']['frequency']['conditions']['observe/4']['probability']['scored_roots'] == 2
    assert smoke['adoption'] == 'not_assessed_do_not_adopt'


def test_holdout_does_not_change_calibration_selection_or_training():
    train = dataset()
    calibrated = assemble(train.branches + partition_copy(train, 'calibration'))
    heldout = assemble(calibrated.branches + partition_copy(train, 'test'))
    first, second = prepare(calibrated), prepare(heldout)
    assert first['models'] == second['models']
    assert first['selected_probability_baseline'] == second['selected_probability_baseline']
    report = evaluate(heldout, second)
    result = report['models']['frequency']['conditions']['observe/4']
    assert result['probability']['root_count'] == 2
    assert result['early_warnings']
    changed = deepcopy(second)
    changed['models']['frequency']['conditions']['observe/4']['threshold']['threshold'] = .123
    with pytest.raises(ForecastDataError, match='frozen_evaluation_plan_mismatch'):
        evaluate(heldout, changed)
    with pytest.raises(ForecastDataError, match='frozen_evaluation_plan_mismatch'):
        evaluate(heldout, first)


def test_cli_requires_plan_and_preserves_existing_artifact(tmp_path):
    data = dataset()
    source = tmp_path / 'dataset'
    write_dataset(data, source)
    plan = tmp_path / 'plan.json'
    main(['prepare', '--dataset', str(source), '--output', str(plan)])
    original = plan.read_bytes()
    with pytest.raises(SystemExit):
        main(['prepare', '--dataset', str(source), '--output', str(plan)])
    assert plan.read_bytes() == original
    report = tmp_path / 'report.json'
    main(['evaluate', '--dataset', str(source), '--plan', str(plan), '--output', str(report)])
    assert json.loads(report.read_text())['partition'] == 'test'
