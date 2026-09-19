from copy import deepcopy
import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import intervention_evidence as module
from research.flow_forecast import task_world_interventions as runner
from research.flow_forecast.task_worlds import definition, operation_script
from test_flow_forecast_task_world_interventions import lab as lab


def test_saved_interventions_revalidate_definition_script_and_outputs(lab, tmp_path):
    output = tmp_path / 'batch'
    report = runner.run(tmp_path, 'inventory', output)
    evidence = module.read_interventions(output)
    assert evidence['report'] == report
    assert evidence['container_identities_recorded'] is True


@pytest.mark.parametrize('name', ['implementation', 'execution', 'reservation-2', 'result-2', 'container-2'])
def test_changed_artifacts_are_rejected(lab, tmp_path, name):
    output = tmp_path / 'batch'
    runner.run(tmp_path, 'calendar', output)
    path = output / (name + '.json')
    value = json.loads(path.read_text())
    value['unexpected'] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        module.read_interventions(output)


def test_finite_result_cannot_be_promoted_even_with_new_report_hash(lab, tmp_path):
    output = tmp_path / 'batch'
    runner.run(tmp_path, 'ledger', output)
    path = output / 'report.json'
    value = json.loads(path.read_text())
    value['semantic_truth_promoted'] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        module.read_interventions(output)


@pytest.mark.parametrize('changed', [None, 'command', 'context', 'definition', 'output'])
def test_binding_requires_same_computation_and_environment(lab, tmp_path, monkeypatch, changed):
    output = tmp_path / 'batch'
    runner.run(tmp_path, 'inventory', output)
    evidence = module.read_interventions(output)
    row = {'step_id': 'a' * 32, 'dispatched': True, 'command_sha': hashlib.sha256(
        operation_script('inventory', 2, 'public', '172.18.0.2', 'a' * 32).encode()).hexdigest(),
        'observation': {'body_sha': evidence['report']['results'][0]['output_sha']}}
    capture = {'intent': {'root': 'b' * 32, 'world': 'inventory', 'variant': 'public',
                          'definition': definition('inventory')},
               'execution': deepcopy(evidence['execution']),
               'report': {'conditions': [{'steps': [{}, row]}]}}
    if changed == 'command':
        row['command_sha'] = 'c' * 64
    elif changed == 'context':
        capture['execution']['context_sha'] = 'c' * 64
    elif changed == 'definition':
        capture['intent']['definition']['program'] = 'result={}'
    elif changed == 'output':
        row['observation']['body_sha'] = 'c' * 64
    monkeypatch.setattr(module, 'read_capture', lambda _: (None, capture))
    if changed:
        with pytest.raises(ForecastDataError):
            module.bind_capture(tmp_path, output)
    else:
        result = module.bind_capture(tmp_path, output)
        assert result['capture_report_sha'] == digest(capture['report'])
        assert len(result['changed_cases']) == 2 and result['semantic_truth_promoted'] is False
