"""One local, tool-free Ticket generation with observed manifest continuity.

This development probe is deliberately not an accepted evaluation receipt:
matching server-reported manifests do not attest the weights used by inference.
"""
import argparse
from copy import deepcopy
from dataclasses import asdict
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.models import utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .provenance import source_provenance
from .task_catalog import _write_private
from .ticket_plan_provider import INSTRUCTIONS, SCHEMA, TASK, Plan, prompt

MODEL = 'qwen3:8b'
LIMIT = 1024 * 1024


def request(revision=2):
    if type(revision) is not int or revision not in (1, 2):
        raise LabError('invalid_local_request_revision')
    schema = deepcopy(SCHEMA)
    if revision == 2:
        propose, refused = deepcopy(schema), deepcopy(schema)
        propose['properties']['status'] = {'const': 'propose'}
        refused['properties']['status'] = {'const': 'refused'}
        refused['properties']['operations']['maxItems'] = 0
        refused['properties']['export'] = {'const': 'public'}
        schema = {'oneOf': [propose, refused]}
    return {'model': MODEL, 'system': INSTRUCTIONS,
            'prompt': prompt([], 'benign_task', {'task': TASK}),
            'format': schema, 'stream': False, 'think': False,
            'options': {'num_predict': 256, 'num_ctx': 4096, 'temperature': 0}}


def exchange(method, path, payload=None):
    # Fixed loopback host; no proxies, redirects, tools, pull, retries or files.
    connection = http.client.HTTPConnection('127.0.0.1', 11434, timeout=55)
    try:
        connection.request(method, path, body=canonical(payload).encode() if payload is not None else None,
                           headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            raise LabError('local_model_http_failure')
        raw = response.read(LIMIT + 1)
        if not raw or len(raw) > LIMIT:
            raise LabError('local_model_response_limit')
        return json.loads(raw)
    finally:
        connection.close()


def identity(tags, server):
    try:
        matches = [item for item in tags['models'] if item['name'] == MODEL]
        if len(matches) != 1:
            raise ValueError
        model = matches[0]
        if (type(model['digest']) is not str or re.fullmatch('[a-f0-9]{64}', model['digest']) is None
                or type(model['size']) is not int or model['size'] <= 0
                or type(server['version']) is not str
                or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', server['version']) is None):
            raise ValueError
        return {'model': MODEL, 'manifest_digest': model['digest'],
                'size': model['size'], 'server_version': server['version']}
    except (KeyError, TypeError, ValueError):
        raise LabError('invalid_local_model_identity') from None


def snapshot():
    return identity(exchange('GET', '/api/tags'), exchange('GET', '/api/version'))


def generate():
    before = snapshot()
    raw = exchange('POST', '/api/generate', request())
    after = snapshot()
    return {'before': before, 'response': raw, 'after': after, 'request_revision': 2}


def metadata(observation):
    try:
        if type(observation) is not dict or set(observation) not in ({'before', 'response', 'after'},
                {'before', 'response', 'after', 'request_revision'}):
            raise ValueError
        if 'request_revision' in observation and (type(observation['request_revision']) is not int
                                                   or observation['request_revision'] != 2):
            raise ValueError
        before, after, raw = (observation[k] for k in ('before', 'after', 'response'))
        expected = identity({'models': [{'name': before['model'], 'digest': before['manifest_digest'],
                                        'size': before['size']}]}, {'version': before['server_version']})
        if before != expected or after != before:
            raise ValueError
        if (raw['model'] != MODEL or raw['done'] is not True or raw['done_reason'] != 'stop'
                or raw.get('tool_calls') or raw.get('thinking')
                or type(raw['response']) is not str or len(raw['response'].encode()) > 16384):
            raise ValueError
        for key in ('prompt_eval_count', 'eval_count', 'total_duration', 'load_duration'):
            if type(raw[key]) is not int or raw[key] < 0:
                raise ValueError
        return {'identity': before,
                'observed_manifest_unchanged': True,
                'resolved_model_verified': False, 'accepted_independent_groups': 0,
                'usage': {k: raw[k] for k in ('prompt_eval_count', 'eval_count', 'total_duration', 'load_duration')},
                'provider_cost': None, 'pricing_source': None}
    except (KeyError, TypeError, ValueError, LabError):
        raise LabError('invalid_local_generation_observation') from None


def validate(observation):
    evidence = metadata(observation)
    try:
        plan = Plan.parse(json.loads(observation['response']['response']))
        if not plan.executable():
            raise ValueError
        return {**evidence, 'plan': json.loads(canonical(asdict(plan)))}
    except (TypeError, ValueError, LabError):
        raise LabError('invalid_local_generation_plan') from None


def worker():
    try:
        # Parent enforces the total wall deadline, including all five requests.
        raw = canonical(generate()).encode()
        if len(raw) > LIMIT:
            return 1
        sys.stdout.buffer.write(raw)
        return 0
    except Exception:
        return 1


def run(output, *, timeout=60):
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise LabError('invalid_local_generation_budget')
    root = Path(__file__).resolve().parents[2]
    implementation = source_provenance(root)
    output.mkdir(mode=0o700)
    intent = {'schema': 1, 'call_id': uuid.uuid4().hex, 'started_at': utc_now(),
              'request': request(), 'implementation_sha': digest(implementation),
              'maximum_model_calls': 1, 'maximum_seconds': timeout,
              'maximum_response_bytes': LIMIT, 'development_used': True}
    for name, value in [('implementation', implementation), ('reservation', intent)]:
        _write_private(output / (name + '.json'), canonical(value).encode())
    started = time.monotonic()
    result = {'schema': 1, 'status': 'not_completed', 'reason': None,
              'reservation_sha': digest(intent), 'generation_requests_reserved': 1,
              'actual_generation_requests': None, 'accepted_independent_groups': 0}
    try:
        process = subprocess.run([sys.executable, '-m', __package__ + '.ollama_ticket_generation', '--worker'],
                                 cwd=root, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=timeout, check=False)
        if process.returncode != 0 or not 0 < len(process.stdout) <= LIMIT:
            raise LabError('local_generation_failed')
        observation = json.loads(process.stdout)
        _write_private(output / 'observation.json', canonical(observation).encode())
        result['actual_generation_requests'] = 1
        result['observation_sha'] = digest(observation)
        # Invalid plans still consumed tokens; keep their validated metadata.
        result['generation_observation'] = metadata(observation)
        evidence = validate(observation)
        if observation.get('request_revision') != 2:
            raise LabError('local_generation_request_mismatch')
        if source_provenance(root) != implementation:
            raise LabError('local_generation_implementation_changed')
        result.update(status='completed', observation_sha=digest(observation), evidence=evidence)
    except subprocess.TimeoutExpired:
        # Killing our client does not establish that Ollama stopped inference.
        result['reason'] = 'local_generation_timeout_server_completion_unknown'
    except (OSError, ValueError, LabError):
        result['reason'] = 'local_generation_failed'
    except BaseException:
        result['reason'] = 'local_generation_interrupted_server_completion_unknown'
        raise
    finally:
        result['elapsed_ms'] = int((time.monotonic() - started) * 1000)
        _write_private(output / 'result.json', canonical(result).encode())
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.worker:
        return worker()
    if args.output is None:
        parser.error('--output is required')
    result = run(args.output)
    print(canonical(result))
    return 0 if result['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
