import json
import subprocess
from types import SimpleNamespace

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import ollama_ticket_generation as local


def observation():
    identity = {'model': local.MODEL, 'manifest_digest': 'a' * 64,
                'size': 123, 'server_version': '0.34.2'}
    return {'before': identity, 'after': dict(identity), 'response': {
        'model': local.MODEL, 'done': True, 'done_reason': 'stop',
        'response': json.dumps({'status': 'propose', 'operations': ['resolve', 'query', 'send'], 'export': 'public'}),
        'prompt_eval_count': 12, 'eval_count': 20, 'total_duration': 123, 'load_duration': 10}}


@pytest.mark.parametrize('change', [
    lambda x: x['after'].update(manifest_digest='b' * 64),
    lambda x: x['after'].update(server_version='0.34.3'),
    lambda x: x['response'].update(done_reason='length'),
    lambda x: x['response'].update(model='another:latest'),
    lambda x: x['response'].update(tool_calls=[{'name': 'exec'}]),
    lambda x: x['response'].update(response='{}'),
    lambda x: x['response'].update(eval_count=True),
    lambda x: x['response'].update(response=json.dumps({'status': 'refused',
        'operations': ['resolve', 'query', 'send'], 'export': 'public'})),
])
def test_rejects_unbound_or_incomplete_observation(change):
    value = observation()
    change(value)
    with pytest.raises(LabError):
        local.validate(value)


def test_matching_identity_does_not_attest_weights_or_price():
    result = local.validate(observation())
    assert result['observed_manifest_unchanged']
    assert result['resolved_model_verified'] is False
    assert result['provider_cost'] is None
    assert result['accepted_independent_groups'] == 0


def test_reservation_precedes_only_child_and_cannot_overwrite(tmp_path, monkeypatch):
    output = tmp_path / 'run'
    calls = []
    def execute(command, **kwargs):
        intent = json.loads((output / 'reservation.json').read_text())
        assert intent['maximum_model_calls'] == 1
        assert kwargs['env'] == {} and kwargs['timeout'] == 60
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(observation()).encode())
    monkeypatch.setattr(local.subprocess, 'run', execute)
    result = local.run(output)
    assert result['status'] == 'completed'
    assert result['actual_generation_requests'] == 1
    with pytest.raises(FileExistsError):
        local.run(output)
    assert len(calls) == 1


def test_timeout_retains_reservation_without_retry_or_claimed_server_stop(tmp_path, monkeypatch):
    calls = []
    def execute(command, **kwargs):
        calls.append(command)
        raise subprocess.TimeoutExpired(command, kwargs['timeout'])
    monkeypatch.setattr(local.subprocess, 'run', execute)
    result = local.run(tmp_path / 'run')
    assert len(calls) == 1
    assert result['actual_generation_requests'] is None
    assert result['reason'] == 'local_generation_timeout_server_completion_unknown'
    assert (tmp_path / 'run' / 'reservation.json').is_file()


def test_worker_only_fixed_metadata_and_one_generation(monkeypatch):
    calls = []
    def exchange(method, path, payload=None):
        calls.append((method, path))
        if path == '/api/tags':
            return {'models': [{'name': local.MODEL, 'digest': 'a' * 64, 'size': 123}]}
        if path == '/api/version':
            return {'version': '0.34.2'}
        assert payload == local.request()
        assert 'tools' not in payload and payload['stream'] is False
        return observation()['response']
    monkeypatch.setattr(local, 'exchange', exchange)
    local.validate(local.generate())
    assert calls == [('GET', '/api/tags'), ('GET', '/api/version'), ('POST', '/api/generate'),
                     ('GET', '/api/tags'), ('GET', '/api/version')]


@pytest.mark.parametrize('status,body', [(302, b'{}'), (200, b'x' * (local.LIMIT + 1))])
def test_http_rejects_redirect_and_oversize_closes_connection(status, body, monkeypatch):
    calls = []
    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ('127.0.0.1', 11434)
        def request(self, *args, **kwargs):
            calls.append('request')
        def getresponse(self):
            return SimpleNamespace(status=status, read=lambda limit: body)
        def close(self):
            calls.append('close')
    monkeypatch.setattr(local.http.client, 'HTTPConnection', Connection)
    with pytest.raises(LabError):
        local.exchange('GET', '/api/tags')
    assert calls == ['request', 'close']
