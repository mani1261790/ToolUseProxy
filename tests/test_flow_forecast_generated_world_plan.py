import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import generated_world_plan as module, task_world_collection, task_world_import
from research.flow_forecast.world_plan_provider import WorldPlanProvider
from test_flow_lab_codex_agent import events, executable
from test_flow_forecast_world_plan_provider import PLAN
from test_flow_forecast_task_world_collection import lab as lab


def provider(tmp_path, value=PLAN):
    return WorldPlanProvider('fixture-model', executable=executable(tmp_path, f'print({events(value).decode()!r})'))


def test_one_call_sealed_and_reloaded_without_claiming_model_resolution(tmp_path):
    out = tmp_path / 'prepared'
    result = module.prepare('inventory', provider(tmp_path), out, timeout=2)
    frozen = module.load(out)
    assert result['status'] == 'prepared' and result['costs']['charged_calls'] == 1
    assert frozen['world'] == 'inventory' and frozen['plan'] == PLAN
    assert frozen['generation']['resolved_model_verified'] is False
    with pytest.raises(FileExistsError):
        module.prepare('inventory', provider(tmp_path), out)


@pytest.mark.parametrize('value', [{**PLAN, 'operations': ['load', 'send']},
                                   {'status': 'refused', 'operations': [], 'export': 'public'}])
def test_rejected_plans_keep_charged_execution_without_retry(tmp_path, value):
    out = tmp_path / 'prepared'
    result = module.prepare('ledger', provider(tmp_path, value), out, timeout=2)
    assert result['status'] == 'not_prepared' and result['rejection'] == 'world_plan_not_executable'
    assert result['costs']['charged_calls'] == 1
    assert result['call']['execution'] is not None
    assert not (out / 'generated-plan.json').exists()


@pytest.mark.parametrize('name', ['request', 'implementation', 'reservation', 'call-result', 'generated-plan'])
def test_changed_artifact_rejected(tmp_path, name):
    out = tmp_path / 'prepared'
    module.prepare('calendar', provider(tmp_path), out, timeout=2)
    path = out / (name + '.json')
    value = json.loads(path.read_text())
    if name == 'reservation':
        value['call_id'] = 'other'
    elif name == 'call-result':
        value['costs']['charged_calls'] = 0
    else:
        value['tampered'] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        module.load(out)


def test_interrupted_call_is_charged_without_completion(tmp_path):
    class Interrupted:
        model_id = 'fixture-model'
        last_execution = last_evidence = None
        def propose(self, *args, **kwargs):
            assert (tmp_path / 'prepared' / 'reservation.json').exists()
            raise KeyboardInterrupt
    out = tmp_path / 'prepared'
    with pytest.raises(KeyboardInterrupt):
        module.prepare('inventory', Interrupted(), out)
    result = json.loads((out / 'call-result.json').read_text())
    assert result['costs']['charged_calls'] == 1 and result['costs']['failed_calls'] == 1
    assert result['costs']['known_token_totals'] is None
    assert not (out / 'generated-plan.json').exists()


def test_plan_binds_capture_before_trials(lab, tmp_path):
    out = tmp_path / 'prepared'
    module.prepare('inventory', provider(tmp_path), out, timeout=2)
    frozen = module.load(out)
    capture = tmp_path / 'capture'
    task_world_collection.run(tmp_path, 'inventory', 'public', capture, generation=frozen)
    _, audit = task_world_import.read_capture(capture)
    assert audit['generator_evidence'] == frozen
    with pytest.raises(Exception, match='world_generation_plan_mismatch'):
        task_world_collection.run(tmp_path, 'ledger', 'public', tmp_path / 'wrong', generation=frozen)
    assert not (tmp_path / 'wrong').exists()


def test_generated_world_collection_uses_original_receipt_and_rejects_reuse(lab, tmp_path):
    from research.flow_forecast import task_catalog, generator_strata
    out = tmp_path / 'prepared'
    module.prepare('inventory', provider(tmp_path), out, timeout=2)
    frozen = module.load(out)
    captures = []
    for number in range(2):
        capture = tmp_path / f'capture-{number}'
        task_world_collection.run(tmp_path, 'inventory', 'public', capture, generation=frozen)
        captures.append(str(capture))
    for count in (1, 2):
        paths = tmp_path / f'paths-{count}.json'
        paths.write_text(json.dumps(captures[:count]))
        collection = tmp_path / f'collection-{count}'
        task_catalog.main(['--task-worlds', str(paths), '--output', str(collection)])
        data, _, audit = task_catalog.read_collection(collection)
        assert audit['grouped_root_count'] == 1
        identity = generator_strata.collection_identity(collection)
        if count == 1:
            strata = generator_strata.load(data, collection, identity)
            assert set(strata['group_labels'].values()) == {'generator/requested/fixture-model'}
            assert strata['summary']['validated_plan_receipts'] == 1
        else:
            with pytest.raises(ForecastDataError, match='generation_receipt_reused'):
                generator_strata.load(data, collection, identity)
