"""Local execution evidence, not provider-signed model identity or independence."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import re

from .agent import Proposal
from .models import RecordError, canonical, identifier, version
from .preflight import LabError


def sha(raw: bytes):
    return hashlib.sha256(raw).hexdigest()


def proposal_sha(proposal: Proposal):
    return sha(canonical(asdict(proposal)).encode())


def capture(*, events: bytes, prompt: bytes, proposal: Proposal, model: str,
            cli_version: str, call_id: str, elapsed_ms: int):
    """Keep only structural identities/costs; never store raw CLI diagnostics."""
    turns, threads = [], []
    for line in events.splitlines():
        event = json.loads(line)
        if event.get('type') == 'turn.completed':
            turns.append(event)
        if event.get('type') == 'thread.started':
            thread = event.get('thread_id')
            if not isinstance(thread, str) or not 1 <= len(thread) <= 128:
                raise LabError('invalid_generation_evidence')
            threads.append(sha(thread.encode()))
    if len(turns) != 1 or len(threads) > 1:
        raise LabError('invalid_generation_evidence')
    usage = turns[0].get('usage')
    if usage is not None:
        if type(usage) is not dict:
            raise LabError('invalid_generation_evidence')
        usage = {key: usage.get(key) for key in ('input_tokens', 'cached_input_tokens', 'output_tokens')}
    evidence = {
        'schema': 1, 'call_id': call_id, 'requested_model': model,
        'resolved_model': None, 'resolved_model_verified': False,
        'cli_version': cli_version, 'thread_sha': threads[0] if threads else None,
        'events_sha': sha(events), 'prompt_sha': sha(prompt),
        'proposal_sha': proposal_sha(proposal), 'usage': usage, 'elapsed_ms': elapsed_ms,
        'scope': 'local_cli_execution_not_provider_attestation',
    }
    validate(evidence, proposal, model)
    return evidence


def validate(evidence, proposal, model):
    try:
        if (type(evidence) is not dict or set(evidence) != {
                'schema', 'call_id', 'requested_model', 'resolved_model', 'resolved_model_verified',
                'cli_version', 'thread_sha', 'events_sha', 'prompt_sha', 'proposal_sha', 'usage',
                'elapsed_ms', 'scope'} or type(evidence['schema']) is not int or evidence['schema'] != 1
                or evidence['requested_model'] != model or evidence['resolved_model'] is not None
                or evidence['resolved_model_verified'] is not False
                or evidence['scope'] != 'local_cli_execution_not_provider_attestation'
                or evidence['proposal_sha'] != proposal_sha(proposal)):
            raise ValueError
        version(evidence['requested_model'])
        identifier(evidence['call_id'])
        if (not isinstance(evidence['cli_version'], str)
                or re.fullmatch(r'codex-cli [0-9]+\.[0-9]+\.[0-9]+', evidence['cli_version']) is None):
            raise ValueError
        for key in ('events_sha', 'prompt_sha', 'proposal_sha', 'thread_sha'):
            value = evidence[key]
            if key == 'thread_sha' and value is None:
                continue
            if not isinstance(value, str) or re.fullmatch(r'[a-f0-9]{64}', value) is None:
                raise ValueError
        if type(evidence['elapsed_ms']) is not int or not 0 <= evidence['elapsed_ms'] <= 120000:
            raise ValueError
        usage = evidence['usage']
        if usage is not None and (type(usage) is not dict or set(usage) != {
                'input_tokens', 'cached_input_tokens', 'output_tokens'} or any(
                type(value) is not int or not 0 <= value <= 1000000000 for value in usage.values())
                or usage['cached_input_tokens'] > usage['input_tokens']):
            raise ValueError
    except (ValueError, TypeError, KeyError, RecordError):
        raise LabError('invalid_generation_evidence') from None
