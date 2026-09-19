from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_lab.generation_evidence import validate
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import generated_ticket, ollama_ticket_provider as provider
from research.flow_forecast.ticket_plan_provider import Plan
from test_flow_forecast_ollama_ticket_generation import observation


def response():
    value = observation()
    value['response']['prompt_eval_cached_count'] = 0
    return value


def replay(monkeypatch, output, value):
    calls = []
    def execute(command, **kwargs):
        reservation = json.loads((output / 'reservation.json').read_text())
        assert reservation['outcome'] == 'pending'
        assert reservation['execution'] is None and reservation['generation'] is None
        assert kwargs['env'] == {} and kwargs['timeout'] <= 60
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())
    monkeypatch.setattr(provider.subprocess, 'run', execute)
    return calls


def test_provider_seals_actual_response_and_costs_after_pre_call_reservation(tmp_path, monkeypatch):
    out = tmp_path / 'prepared'
    calls = replay(monkeypatch, out, response())
    result = generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    assert result['status'] == 'prepared' and len(calls) == 1
    frozen = generated_ticket.load(out)
    assert frozen['generation']['schema'] == 3
    assert frozen['generation']['reported_model'] == 'qwen3:8b'
    assert frozen['model'] == 'ollama-qwen3-8b'
    assert frozen['generation']['resolved_model_verified'] is False
    assert result['costs']['known_token_totals']['output_tokens'] == 20
    assert result['costs']['provider_cost'] is None
    with pytest.raises(FileExistsError):
        generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    assert len(calls) == 1


def test_rejected_plan_keeps_execution_cost_without_prepared_plan(tmp_path, monkeypatch):
    out = tmp_path / 'prepared'
    value = response()
    value['response']['response'] = json.dumps({'status': 'refused',
        'operations': ['resolve', 'query', 'send'], 'export': 'public'})
    calls = replay(monkeypatch, out, value)
    result = generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    assert len(calls) == 1 and result['status'] == 'not_prepared'
    assert result['call']['execution']['schema'] == 3
    assert result['costs']['failed_calls'] == 1
    assert result['costs']['known_token_totals']['output_tokens'] == 20
    assert not (out / 'generated-plan.json').exists()


@pytest.mark.parametrize('change', [
    lambda x: x['after'].update(manifest_digest='b' * 64),
    lambda x: x['response'].update(eval_count=21),
    lambda x: x['response'].update(response='{}'),
])
def test_raw_observation_rechecked_when_loading_plan(tmp_path, monkeypatch, change):
    out = tmp_path / 'prepared'
    replay(monkeypatch, out, response())
    generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    path = out / 'ollama-observation.json'
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        generated_ticket.load(out)


def test_missing_cache_usage_is_not_zero():
    receipt = provider.receipt(observation(), 'a' * 32, 12)
    assert receipt['usage'] is None


@pytest.mark.parametrize('field,value', [
    ('endpoint', 'https://example.com/api/generate'),
    ('reported_model', 'another:8b'),
    ('resolved_model_verified', True),
    ('model_identity_after', {'model': 'qwen3:8b', 'manifest_digest': 'b' * 64,
                              'size': 123, 'server_version': '0.34.2'}),
])
def test_common_receipt_validator_rejects_forged_scope(field, value):
    receipt = provider.receipt(response(), 'a' * 32, 12)
    receipt[field] = deepcopy(value)
    with pytest.raises(LabError):
        validate(receipt, None, provider.MODEL_ID)


def test_plan_receipt_binds_proposal():
    value = response()
    plan = Plan.parse(json.loads(value['response']['response']))
    receipt = provider.receipt(value, 'a' * 32, 12, plan)
    with pytest.raises(LabError):
        validate(receipt, Plan('refused', (), 'public'), provider.MODEL_ID)
    with pytest.raises(LabError, match='local_generation_plan_mismatch'):
        provider.receipt(value, 'a' * 32, 12, Plan('propose', ('resolve', 'query', 'send'), 'include_private'))


def test_resealed_plan_cannot_replace_actual_generated_plan(tmp_path, monkeypatch):
    from hook_monitor.evaluation.flow_forecast.prefix import digest
    from hook_monitor.evaluation.flow_lab.generation_evidence import proposal_sha
    out = tmp_path / 'prepared'
    replay(monkeypatch, out, response())
    generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    path = out / 'generated-plan.json'
    frozen = json.loads(path.read_text())
    frozen['plan']['export'] = 'include_private'
    frozen['generation']['proposal_sha'] = proposal_sha(Plan.parse(frozen['plan']))
    frozen['prepared_sha'] = digest({k: v for k, v in frozen.items() if k != 'prepared_sha'})
    path.write_text(json.dumps(frozen))
    path = out / 'call-result.json'
    result = json.loads(path.read_text())
    result['call']['proposal'] = frozen['plan']
    result['call']['generation'] = frozen['generation']
    path.write_text(json.dumps(result))
    with pytest.raises(ForecastDataError):
        generated_ticket.load(out)


def test_old_observation_remains_bound_to_old_request_without_relabeling():
    from research.flow_forecast import ollama_ticket_generation as local
    value = response()
    value.pop('request_revision')
    old = provider.receipt(value, 'a' * 32, 12)
    assert old['request_sha'] == local.digest(local.request(1))
    assert old['request_sha'] != local.digest(local.request())


def test_new_execution_rejects_unversioned_worker_output(tmp_path, monkeypatch):
    value = response()
    value.pop('request_revision')
    out = tmp_path / 'prepared'
    calls = replay(monkeypatch, out, value)
    result = generated_ticket.prepare(provider.OllamaTicketProvider('qwen3:8b', out), out)
    assert len(calls) == 1 and result['status'] == 'not_prepared'
    assert not (out / 'generated-plan.json').exists()
