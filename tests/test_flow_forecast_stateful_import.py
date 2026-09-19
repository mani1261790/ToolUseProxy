import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.stateful_collection import run
from research.flow_forecast.stateful_import import read_capture
from test_flow_forecast_stateful_collection import PLAN, lab  # noqa: F401


@pytest.mark.usefixtures('lab')
def test_saved_capture_reconstructs_dataset(tmp_path):
    output = tmp_path / 'capture'
    report = run(tmp_path, PLAN, output)
    data, audit = read_capture(output)
    assert audit['report'] == report
    assert len(data.branches) == 8


@pytest.mark.parametrize('name', ['intent', 'execution', 'report', 'implementation', 'observe',
                                  'observe-step-1', 'observe-guard-1', 'reservation-4'])
@pytest.mark.usefixtures('lab')
def test_changed_saved_artifact_is_rejected(tmp_path, name):
    output = tmp_path / 'capture'
    run(tmp_path, PLAN, output)
    path = output / (name + '.json')
    value = json.loads(path.read_text())
    value['tampered'] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        read_capture(output)


@pytest.mark.usefixtures('lab')
def test_collection_cli_and_model_strata_use_original_generation(tmp_path):
    from research.flow_forecast import generated_stateful, generator_strata, task_catalog
    from test_flow_forecast_generated_stateful import Provider
    from test_flow_lab_task_assignment import binding
    prepared, output = tmp_path / 'prepared', tmp_path / 'capture'
    generated_stateful.prepare(binding(), Provider(), prepared)
    frozen = generated_stateful.load(prepared)
    run(tmp_path, frozen['plan'], output, generation=frozen)
    paths = tmp_path / 'paths.json'
    paths.write_text(json.dumps([str(output)]))
    collection = tmp_path / 'collection'
    task_catalog.main(['--stateful-captures', str(paths), '--output', str(collection)])
    data, _, audit = task_catalog.read_collection(collection)
    assert audit['independence_verified'] is False
    result = generator_strata.load(data, collection, generator_strata.collection_identity(collection))
    assert set(result['group_labels'].values()) == {'generator/requested/fixture-model'}
    assert result['summary']['validated_plan_receipts'] == 1
    assert result['summary']['resolved_model_versions_verified'] is False


@pytest.mark.usefixtures('lab')
def test_control_failure_cannot_be_hidden_by_updating_report(tmp_path):
    output = tmp_path / 'capture'
    run(tmp_path, PLAN, output)
    condition = json.loads((output / 'observe.json').read_text())
    condition['controls'][2]['process_started'] = 'yes'
    (output / 'observe.json').write_text(json.dumps(condition))
    report = json.loads((output / 'report.json').read_text())
    report['conditions'][0] = condition
    (output / 'report.json').write_text(json.dumps(report))
    with pytest.raises(ForecastDataError, match='stateful_controls_failed'):
        read_capture(output)


@pytest.mark.usefixtures('lab')
def test_replaying_same_generated_plan_does_not_duplicate_model_receipts(tmp_path, monkeypatch):
    from research.flow_forecast import generated_stateful, generator_strata, task_catalog
    from test_flow_forecast_generated_stateful import Provider
    from test_flow_forecast_generator_strata import seal_only
    from test_flow_lab_task_assignment import binding
    prepared = tmp_path / 'prepared'
    generated_stateful.prepare(binding(), Provider(), prepared)
    frozen = generated_stateful.load(prepared)
    outputs = (tmp_path / 'first', tmp_path / 'second')
    for output in outputs:
        run(tmp_path, frozen['plan'], output, generation=frozen)
    data, audit, catalog, _ = task_catalog.collect_stateful_captures(outputs)
    assert audit['grouped_root_count'] == 1
    path = seal_only(tmp_path)
    monkeypatch.setattr(generator_strata, 'read_collection', lambda _: (data, catalog, audit))
    with pytest.raises(ForecastDataError, match='generation_receipt_reused'):
        generator_strata.load(data, path, generator_strata.collection_identity(path))
