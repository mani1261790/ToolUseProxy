"""One bounded, tool-free Responses request for a closed synthetic world."""
import hashlib
import http.client
import json
import os
import subprocess
import sys
import time
import uuid

from hook_monitor.evaluation.flow_lab.generation_evidence import validate
from hook_monitor.evaluation.flow_lab.models import RecordError, version
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .world_plan_provider import INSTRUCTIONS, SCHEMA, Plan, prompt

ENDPOINT = 'https://api.openai.com/v1/responses'
MAX_RESPONSE_BYTES = 256 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def request(model, text):
    version(model)
    return {'model': model, 'instructions': INSTRUCTIONS, 'input': text,
            'tools': [], 'tool_choice': 'none', 'store': False, 'stream': False,
            'max_output_tokens': 1024,
            'text': {'format': {'type': 'json_schema', 'name': 'closed_world_plan',
                                'strict': True, 'schema': SCHEMA}}}


def receipt(raw, payload, text, call_id, elapsed_ms, proposal=None):
    try:
        response = json.loads(raw)
        if (response['object'] != 'response' or not isinstance(response['id'], str)
                or not 1 <= len(response['id']) <= 256):
            raise ValueError
        version(response['model'])
        usage = response.get('usage')
        if usage is not None:
            usage = {'input_tokens': usage['input_tokens'], 'output_tokens': usage['output_tokens'],
                     'cached_input_tokens': usage['input_tokens_details']['cached_tokens']}
        from dataclasses import asdict
        value = {'schema': 2, 'call_id': call_id, 'requested_model': payload['model'],
                 'resolved_model': None, 'resolved_model_verified': False,
                 'reported_model': response['model'], 'endpoint': ENDPOINT,
                 'request_sha': hashlib.sha256(encoded(payload)).hexdigest(),
                 'response_id_sha': hashlib.sha256(response['id'].encode()).hexdigest(),
                 'cli_version': None, 'thread_sha': None,
                 'events_sha': hashlib.sha256(raw).hexdigest(),
                 'prompt_sha': hashlib.sha256(text.encode()).hexdigest(),
                 'proposal_sha': hashlib.sha256(encoded(asdict(proposal))).hexdigest() if proposal is not None else None,
                 'usage': usage, 'elapsed_ms': elapsed_ms, 'scope': 'local_https_response_metadata'}
        validate(value, proposal, payload['model'])
        return value
    except (KeyError, TypeError, ValueError, RecordError):
        raise LabError('invalid_api_generation_evidence') from None


def parse_plan(raw):
    try:
        value = json.loads(raw)
        if (value['object'] != 'response' or value['status'] != 'completed'
                or value.get('error') is not None or value.get('incomplete_details') is not None
                or type(value['output']) is not list):
            raise ValueError
        messages = []
        for item in value['output']:
            if item['type'] == 'reasoning':
                continue
            if (item['type'] != 'message' or item['role'] != 'assistant'
                    or item['status'] != 'completed' or type(item['content']) is not list):
                raise ValueError
            for content in item['content']:
                if content['type'] != 'output_text' or type(content['text']) is not str:
                    raise ValueError
                messages.append(content['text'])
        if len(messages) != 1 or len(messages[0].encode()) > 16384:
            raise ValueError
        return Plan.parse(json.loads(messages[0]))
    except (KeyError, TypeError, ValueError, RecordError):
        raise LabError('invalid_model_proposal') from None


class APIWorldPlanProvider:
    def __init__(self, model_id):
        version(model_id)
        self.model_id = model_id
        self.last_evidence = self.last_execution = None

    def propose(self, feedback, *, task_mode, timeout, max_bytes, task_context=None):
        self.last_evidence = self.last_execution = None
        if type(timeout) not in (int, float) or not 0 < timeout <= 60 or max_bytes != 16384:
            raise LabError('invalid_api_generation_budget')
        text = prompt(feedback, task_mode, task_context)
        payload = request(self.model_id, text)
        key = os.environ.get('OPENAI_API_KEY')
        if not key:
            raise LabError('model_auth_required')
        started, call_id = time.monotonic(), uuid.uuid4().hex
        try:
            result = subprocess.run([sys.executable, '-m', 'research.flow_forecast.api_world_plan'],
                input=encoded(payload), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False, env={'OPENAI_API_KEY': key},
                cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        except subprocess.TimeoutExpired:
            raise LabError('model_timeout') from None
        except OSError:
            raise LabError('model_unavailable') from None
        if result.returncode != 0:
            raise LabError({2: 'model_auth_required', 3: 'model_quota_exhausted'}.get(
                result.returncode, 'model_unavailable'))
        raw = result.stdout
        if not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            raise LabError('invalid_model_proposal')
        elapsed = int((time.monotonic() - started) * 1000)
        self.last_execution = receipt(raw, payload, text, call_id, elapsed)
        plan = parse_plan(raw)
        self.last_evidence = receipt(raw, payload, text, call_id, elapsed, plan)
        from dataclasses import asdict
        return asdict(plan) | {'operations': list(plan.operations)}


def worker():
    # This child has a parent-enforced wall deadline; socket timeouts alone are
    # not a total deadline. No redirects, proxies, retries or configurable host.
    connection = None
    try:
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            return 1
        payload = json.loads(raw)
        if payload != request(payload['model'], payload['input']):
            return 1
        connection = http.client.HTTPSConnection('api.openai.com', timeout=55)
        connection.request('POST', '/v1/responses', body=encoded(payload), headers={
            'Authorization': 'Bearer ' + os.environ['OPENAI_API_KEY'], 'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            return 2 if response.status in (401, 403) else 3 if response.status == 429 else 1
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            return 1
        sys.stdout.buffer.write(body)
        return 0
    except Exception:
        return 1  # Never emit HTTP bodies, credentials or library diagnostics.
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(worker())
