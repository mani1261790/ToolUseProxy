"""Adapt bounded local generation to the existing pre-reserved Ticket collector."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.generation_evidence import proposal_sha, validate
from hook_monitor.evaluation.flow_lab.preflight import LabError
from . import ollama_ticket_generation as local
from .task_catalog import _write_private
from .ticket_plan_provider import Plan, prompt

MODEL_ID = 'ollama-qwen3-8b'


def receipt(observation, call_id, elapsed_ms, proposal=None):
    metadata = local.metadata(observation)
    raw = observation['response']
    if proposal is not None:
        try:
            observed_plan = Plan.parse(json.loads(raw['response']))
            if observed_plan != proposal:
                raise ValueError
        except (TypeError, ValueError, LabError):
            raise LabError('local_generation_plan_mismatch') from None
    # Older servers may omit cache usage. Do not invent a zero for those calls.
    usage = None
    if 'prompt_eval_cached_count' in raw:
        usage = {'input_tokens': raw['prompt_eval_count'], 'output_tokens': raw['eval_count'],
                 'cached_input_tokens': raw['prompt_eval_cached_count']}
    payload = local.request()
    result = {'schema': 3, 'call_id': call_id, 'requested_model': MODEL_ID,
              'resolved_model': None, 'resolved_model_verified': False,
              'reported_model': raw['model'], 'endpoint': 'http://127.0.0.1:11434/api/generate',
              'request_sha': digest(payload), 'cli_version': None, 'thread_sha': None,
              'events_sha': digest(observation),
              'prompt_sha': hashlib.sha256(payload['prompt'].encode()).hexdigest(),
              'proposal_sha': proposal_sha(proposal) if proposal is not None else None,
              'usage': usage, 'elapsed_ms': elapsed_ms,
              'scope': 'local_ollama_observed_manifest_not_weight_attestation',
              'model_identity_before': metadata['identity'], 'model_identity_after': observation['after']}
    validate(result, proposal, MODEL_ID)
    return result


class OllamaTicketProvider:
    def __init__(self, model_id, output):
        if model_id not in (MODEL_ID, local.MODEL):
            raise LabError('unsupported_local_ticket_model')
        self.model_id, self.output = MODEL_ID, output
        self.last_execution = self.last_evidence = None

    def propose(self, feedback, *, task_mode, timeout, max_bytes, task_context=None):
        self.last_execution = self.last_evidence = None
        if type(timeout) is not int or not 1 <= timeout <= 60 or max_bytes != 16384:
            raise LabError('invalid_local_generation_budget')
        if prompt(feedback, task_mode, task_context) != local.request()['prompt']:
            raise LabError('invalid_ticket_plan_context')
        started, call_id = time.monotonic(), uuid.uuid4().hex
        try:
            process = subprocess.run([sys.executable, '-m', 'research.flow_forecast.ollama_ticket_generation', '--worker'],
                                     cwd=Path(__file__).resolve().parents[2], env={},
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise LabError('model_timeout') from None
        except OSError:
            raise LabError('model_unavailable') from None
        if process.returncode != 0 or not 0 < len(process.stdout) <= local.LIMIT:
            raise LabError('model_unavailable')
        try:
            observation = json.loads(process.stdout)
            # Preserve the observed response even when its plan is invalid.
            _write_private(self.output / 'ollama-observation.json', canonical(observation).encode())
            elapsed = int((time.monotonic() - started) * 1000)
            self.last_execution = receipt(observation, call_id, elapsed)
            plan = Plan.parse(json.loads(observation['response']['response']))
            self.last_evidence = receipt(observation, call_id, elapsed, plan)
            return json.loads(canonical(asdict(plan)))
        except (KeyError, TypeError, ValueError, LabError):
            raise LabError('invalid_model_proposal') from None
