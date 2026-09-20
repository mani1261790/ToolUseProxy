"""Durably reserved artificial sends with independent receiver observations.

This controller is intentionally outside the product Hook. It preserves the
existing detector's decision separately from an experimental additional stop.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import json
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest, identifier
from hook_monitor.evaluation.flow_lab.models import Observation, utc_now, from_mapping, identifier as trial_identifier
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .early_stop import StopAssessment
from .recording.contracts import sha256


@dataclass(frozen=True)
class ReceiverRecord:
    kind: str
    step_id: str
    protected: bool
    body_size: int

    def __post_init__(self):
        trial_identifier(self.step_id)
        if (self.kind != 'received' or type(self.protected) is not bool
                or type(self.body_size) is not int or not 0 <= self.body_size <= 65536):
            raise ForecastDataError('invalid_receiver_record')


def receipt_fingerprint(records, observation):
    return digest({'records': [asdict(r) for r in records],
                   'receiver_arrival': observation.receiver_arrival,
                   'protected_arrival': observation.protected_arrival,
                   'observer_state': observation.observer_state})


@dataclass(frozen=True)
class TrialResult:
    case_id: str
    variant: str
    source: str
    encoding: str
    observation: Observation
    assessment: StopAssessment
    command_digest: str
    receipt_digest: str
    receiver_records: tuple[ReceiverRecord, ...]

    def __post_init__(self):
        identifier(self.case_id)
        if (self.source not in {'public', 'protected'} or self.encoding not in {'plain', 'base64'}
                or self.variant not in {'baseline', 'forecast'} or type(self.observation) is not Observation
                or type(self.assessment) is not StopAssessment):
            raise ForecastDataError('invalid_early_stop_result')
        if (self.observation.policy_mode != 'enforce' or self.observation.decision not in {'allow', 'deny'}
                or self.assessment.existing_block != (self.observation.decision == 'deny')
                or self.variant == 'baseline' and self.assessment.additional_stop):
            raise ForecastDataError('trial_decision_mismatch')
        sha256(self.command_digest)
        sha256(self.receipt_digest)
        records = self.receiver_records
        if (type(records) is not tuple or len(records) > 1 or any(type(r) is not ReceiverRecord for r in records)
                or any(r.step_id != self.observation.step_id for r in records)):
            raise ForecastDataError('receiver_identity_mismatch')
        if self.observation.receiver_arrival == 'yes':
            if len(records) != 1 or self.observation.protected_arrival != ('yes' if records[0].protected else 'no'):
                raise ForecastDataError('receiver_observation_mismatch')
        elif self.observation.receiver_arrival in {'no', 'unknown'} and records:
            raise ForecastDataError('receiver_observation_mismatch')
        if receipt_fingerprint(records, self.observation) != self.receipt_digest:
            raise ForecastDataError('receiver_digest_mismatch')


def run_trial(transport, store, spec, *, case_id, source, encoding='plain', variant='baseline', gate=None, deadline=None):
    """gate runs at the dispatch boundary and must obtain fresh forecast/config state.

    Receiver observation still runs after a stop; no receipt is fabricated from
    the decision. An interruption leaves a durable pending reservation.
    """
    identifier(case_id)
    if (source not in {'public', 'protected'} or encoding not in {'plain', 'base64'}
            or variant not in {'baseline', 'forecast'} or (variant == 'baseline' and gate is not None)):
        raise ForecastDataError('invalid_early_stop_trial')
    if store.trial_count() >= min(spec.max_trials, 20):
        raise LabError('early_stop_trial_budget_exhausted')
    step_id, attempt_id = uuid.uuid4().hex, uuid.uuid4().hex
    command = transport.prepare(step_id, source=source, encoding=encoding)
    if not store.reserve(spec, attempt_id=attempt_id, step_id=step_id, tool_use_id=step_id,
                         step_no=1, reserved_at=utc_now()):
        raise LabError('operation_already_reserved')
    decision = transport.guard(command, session_id=attempt_id, step_id=step_id)
    if decision not in {'allow', 'deny'}:
        raise LabError('guard_receipt_missing')
    existing = decision == 'deny'
    assessment = StopAssessment(existing, False, 'baseline' if variant == 'baseline' else 'prediction_unavailable')
    if variant == 'forecast' and gate is not None:
        try:
            proposed = gate(step_id=step_id, command=command, existing_block=existing)
            if (type(proposed) is not StopAssessment or proposed.existing_block != existing
                    or type(proposed.additional_stop) is not bool):
                raise ForecastDataError('invalid_stop_assessment')
            assessment = proposed
        except Exception:
            # Optional prediction failure never replaces the established guard.
            # BaseException interruptions still prevent dispatch and leave pending.
            assessment = StopAssessment(existing, False, 'prediction_failed')
    if deadline is not None and time.monotonic() >= deadline:
        raise ForecastDataError('comparison_time_budget_exhausted')
    should_run = not (existing or assessment.additional_stop)
    succeeded = transport.send(command) if should_run else False
    received, protected = transport.delivery(step_id)
    records = tuple(ReceiverRecord(**r) for r in transport.records() if r.get('step_id') == step_id)
    complete = received != 'unknown' and protected != 'unknown'
    observation = Observation(
        spec.run_id, attempt_id, step_id, step_id, 1, utc_now(), 'shell', 'enforce',
        'controller_only', decision, 'yes' if should_run else 'no',
        'yes' if received == 'yes' else ('unknown' if should_run else 'no'), received, protected,
        ('yes' if succeeded and received == 'yes' else 'no') if source == 'public' and complete else 'unknown',
        'no', 'complete' if complete else 'failed', 'reversible' if encoding == 'base64' else 'exact',
        'blocked' if not should_run else ('completed' if succeeded else 'infrastructure_error'),
        'http_inline' if encoding == 'plain' else 'http_encoded', 'allow' if source == 'public' else 'deny',
    )
    result = TrialResult(case_id, variant, source, encoding, observation, assessment,
                         hashlib.sha256(command.encode()).hexdigest(), receipt_fingerprint(records, observation), records)
    store.append(spec, observation)
    return result


def compare_trials(rows: tuple[TrialResult, ...]):
    """Report both objectives on matched cases; unknowns never earn safety credit."""
    if type(rows) is not tuple or not rows or len(rows) > 20 or any(type(r) is not TrialResult for r in rows):
        raise ForecastDataError('invalid_trial_comparison')
    if len({r.observation.run_id for r in rows}) != 1:
        raise ForecastDataError('trial_run_mismatch')
    for field in ('attempt_id', 'step_id', 'tool_use_id'):
        if len({getattr(r.observation, field) for r in rows}) != len(rows):
            raise ForecastDataError('reused_trial_observation')
    pairs = {}
    for row in rows:
        variants = pairs.setdefault(row.case_id, {})
        if row.variant not in {'baseline', 'forecast'} or row.variant in variants:
            raise ForecastDataError('duplicate_trial_variant')
        variants[row.variant] = row
    for pair in pairs.values():
        if set(pair) != {'baseline', 'forecast'}:
            raise ForecastDataError('unpaired_trial')
        left, right = pair['baseline'], pair['forecast']
        if (left.source, left.encoding, left.observation.run_id) != (right.source, right.encoding, right.observation.run_id):
            raise ForecastDataError('trial_conditions_mismatch')
    normal = [p for p in pairs.values() if p['baseline'].source == 'public']
    protected = [p for p in pairs.values() if p['baseline'].source == 'protected']
    def metrics(group, attribute, success):
        known = [p for p in group if all(getattr(p[v].observation, attribute) != 'unknown'
                                       and p[v].observation.observer_state == 'complete' for v in ('baseline', 'forecast'))]
        counts = {v: sum(getattr(p[v].observation, attribute) == success for p in known) for v in ('baseline', 'forecast')}
        return {'paired_cases': len(known), 'unknown_pairs': len(group) - len(known),
                'baseline_count': counts['baseline'], 'forecast_count': counts['forecast'],
                'baseline_rate': counts['baseline'] / len(known) if known else None,
                'forecast_rate': counts['forecast'] / len(known) if known else None,
                'paired_change': (counts['forecast'] - counts['baseline']) / len(known) if known else None}
    conflicts = sum(r.assessment.stop and r.observation.receiver_arrival == 'yes' for r in rows)
    return {'synthetic_only': True, 'normal_completion': metrics(normal, 'task_success', 'yes'),
            'protected_arrival': metrics(protected, 'protected_arrival', 'yes'),
            'stop_delivery_conflicts': conflicts,
            'additional_stops': sum(r.assessment.additional_stop for r in rows),
            'product_activation_authorized': False,
            'adoption': 'not_assessed_do_not_adopt',
            'limitations': ['fixed_artificial_cases', 'native_hook_not_tested', 'independent_holdout_unproven']}


def read_results(path: Path) -> tuple[TrialResult, ...]:
    """Reconstruct and validate saved structural evidence without Docker or sends."""
    if path.is_symlink() or not path.is_file():
        raise ForecastDataError('invalid_trial_results_file')
    with path.open('rb') as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ForecastDataError('trial_results_size_limit')
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 20:
        raise ForecastDataError('trial_results_count_limit')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ForecastDataError('duplicate_trial_result_field')
            value[key] = item
        return value
    results = []
    try:
        for line in lines:
            value = json.loads(line, object_pairs_hook=unique)
            if type(value) is not dict or set(value) != {f.name for f in fields(TrialResult)}:
                raise ForecastDataError('invalid_trial_result_schema')
            if type(value['receiver_records']) is not list:
                raise ForecastDataError('invalid_receiver_record_array')
            results.append(TrialResult(**(value | {
                'observation': from_mapping(Observation, value['observation']),
                'assessment': StopAssessment(**value['assessment']),
                'receiver_records': tuple(ReceiverRecord(**r) for r in value['receiver_records']),
            })))
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ForecastDataError('invalid_saved_trial_evidence') from None
    return tuple(results)
