from copy import deepcopy
import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import api_world_plan as api, generated_world_plan as generated
from research.flow_forecast import task_world_collection, task_world_import
from test_flow_forecast_task_world_collection import lab as lab

PLAN = {'status': 'propose', 'operations': ['load', 'compute', 'save', 'send'], 'export': 'public'}


def response():
    return {'id': 'resp_fixture', 'object': 'response', 'model': 'fixture-reported-model',
            'status': 'completed', 'output': [{'type': 'message', 'role': 'assistant',
                'status': 'completed', 'content': [{'type': 'output_text', 'text': json.dumps(PLAN)}]}],
            'usage': {'input_tokens': 30, 'output_tokens': 10, 'input_tokens_details': {'cached_tokens': 5}}}


@pytest.fixture
def fake(monkeypatch):
    state = {'response': response(), 'calls': []}
    monkeypatch.setenv('OPENAI_API_KEY', 'synthetic-key')
    def run(command, **kwargs):
        state['calls'].append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=api.encoded(state['response']), stderr=b'')
    monkeypatch.setattr(api.subprocess, 'run', run)
    return state


def test_prepared_api_receipt_is_bound_and_reloaded(fake, tmp_path, lab):
    output = tmp_path / 'prepared'
    report = generated.prepare('inventory', api.APIWorldPlanProvider('fixture-alias'), output)
    value = generated.load(output)
    receipt = value['generation']
    assert receipt['schema'] == 2 and receipt['reported_model'] == 'fixture-reported-model'
    assert receipt['requested_model'] == 'fixture-alias' and receipt['cli_version'] is None
    assert not receipt['resolved_model_verified']
    assert report['costs']['known_token_totals']['input_tokens'] == 30
    assert len(fake['calls']) == 1
    command, kwargs = fake['calls'][0]
    payload = json.loads(kwargs['input'])
    assert payload['tools'] == [] and payload['tool_choice'] == 'none' and payload['store'] is False
    assert b'synthetic-key' not in kwargs['input'] and 'synthetic-key' not in str(command)
    assert kwargs['timeout'] == 60 and kwargs['env'] == {'OPENAI_API_KEY': 'synthetic-key'}
    capture = tmp_path / 'capture'
    task_world_collection.run(tmp_path, 'inventory', 'public', capture, generation=value)
    assert task_world_import.read_capture(capture)[1]['generator_evidence'] == value
    from research.flow_forecast import task_catalog, generator_strata
    source = tmp_path / 'inputs.json'
    source.write_text(json.dumps([str(capture)]))
    collection = tmp_path / 'collection'
    task_catalog.main(['--task-worlds', str(source), '--output', str(collection)])
    data, _, _ = task_catalog.read_collection(collection)
    summary = generator_strata.load(data, collection, generator_strata.collection_identity(collection))['summary']
    assert {name for names in summary['provider_reported_models_by_partition'].values()
            for name in names} == {'fixture-reported-model'}
    assert summary['resolved_model_versions_verified'] is False


@pytest.mark.parametrize('change', ['tool', 'incomplete', 'refusal', 'duplicate', 'broken_json'])
def test_rejected_output_retains_usage_without_retry(fake, tmp_path, change):
    value = fake['response']
    if change == 'tool':
        value['output'].append({'type': 'function_call'})
    elif change == 'incomplete':
        value['status'] = 'incomplete'
    elif change == 'refusal':
        value['output'][0]['content'] = [{'type': 'refusal', 'refusal': 'no'}]
    elif change == 'duplicate':
        value['output'].append(deepcopy(value['output'][0]))
    else:
        value['output'][0]['content'][0]['text'] = '{'
    result = generated.prepare('inventory', api.APIWorldPlanProvider('fixture-alias'), tmp_path / 'run')
    assert result['status'] == 'not_prepared' and len(fake['calls']) == 1
    assert result['costs']['calls_with_usage'] == 1
    assert not (tmp_path / 'run' / 'generated-plan.json').exists()


def test_missing_key_never_starts_network_child(monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.setattr(api.subprocess, 'run', lambda *a, **k: pytest.fail('child started'))
    with pytest.raises(LabError, match='model_auth_required'):
        api.APIWorldPlanProvider('fixture').propose([], task_mode='benign_task', timeout=1,
                                                  max_bytes=16384, task_context={'world': 'inventory'})


def test_timeout_has_no_automatic_retry(fake, monkeypatch, tmp_path):
    calls = []
    def timeout(*args, **kwargs):
        calls.append(1)
        raise subprocess.TimeoutExpired('fixture', 1)
    monkeypatch.setattr(api.subprocess, 'run', timeout)
    result = generated.prepare('inventory', api.APIWorldPlanProvider('fixture'), tmp_path / 'run', timeout=1)
    assert result['rejection'] == 'model_timeout' and len(calls) == 1
    assert result['costs']['known_token_totals'] is None


@pytest.mark.parametrize('status,size', [(302, 0), (401, 0), (429, 0), (200, api.MAX_RESPONSE_BYTES + 1)])
def test_worker_never_follows_redirects_or_prints_error_bodies(monkeypatch, status, size):
    connections = []
    class Connection:
        def __init__(self, host, **kwargs):
            assert host == 'api.openai.com'
            connections.append(self)
        def request(self, method, path, **kwargs):
            assert method == 'POST' and path == '/v1/responses'
        def getresponse(self):
            return SimpleNamespace(status=status, read=lambda n: b'x' * min(n, size))
        def close(self):
            self.closed = True
    stdout = io.BytesIO()
    monkeypatch.setattr(api.http.client, 'HTTPSConnection', Connection)
    monkeypatch.setattr(api.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(api.encoded(api.request('fixture', 'x')))))
    monkeypatch.setattr(api.sys, 'stdout', SimpleNamespace(buffer=stdout))
    monkeypatch.setenv('OPENAI_API_KEY', 'synthetic-key')
    assert api.worker() != 0
    assert len(connections) == 1 and connections[0].closed
    assert stdout.getvalue() == b''


def test_execution_and_proposal_must_agree_on_provider_metadata(fake, tmp_path):
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
    output = tmp_path / 'prepared'
    generated.prepare('inventory', api.APIWorldPlanProvider('fixture-alias'), output)
    path = output / 'call-result.json'
    result = json.loads(path.read_text())
    result['call']['execution']['reported_model'] = 'different-model'
    path.write_text(json.dumps(result))
    with pytest.raises(ForecastDataError, match='invalid_world_plan_artifacts'):
        generated.load(output)


def test_rehashed_plan_cannot_change_the_api_request(fake, tmp_path):
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
    output = tmp_path / 'prepared'
    generated.prepare('inventory', api.APIWorldPlanProvider('fixture-alias'), output)
    value = generated.load(output)
    assert 'synthetic-key' not in json.dumps(value)
    value['generation']['request_sha'] = 'f' * 64
    value['prepared_sha'] = digest({k: v for k, v in value.items() if k != 'prepared_sha'})
    with pytest.raises(ForecastDataError, match='invalid_generated_world_plan'):
        generated.validate(value)


@pytest.mark.parametrize('reported', [None, 42])
def test_bad_response_model_is_a_controlled_failure(fake, tmp_path, reported):
    fake['response']['model'] = reported
    result = generated.prepare('inventory', api.APIWorldPlanProvider('fixture-alias'), tmp_path / 'run')
    assert result['status'] == 'not_prepared' and len(fake['calls']) == 1
    assert result['costs']['calls_without_usage'] == 1
