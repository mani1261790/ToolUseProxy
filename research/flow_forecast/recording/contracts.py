"""Version-bound record-only requests; these types grant no execution permission."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import math
import re

from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject, ObservedStep, Prefix, canonical, digest, identifier,
)


MAX_REQUEST_BYTES = 256 * 1024


def sha256(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise ForecastDataError('invalid_recording_digest')


@dataclass(frozen=True)
class Binding:
    workspace_id: str
    session_id: str
    event_id: str
    candidate_id: str
    candidate_digest: str
    protection_digest: str
    policy_digest: str
    prefix_digest: str
    observed_sequence: int
    project_generation: int

    def __post_init__(self):
        for value in (self.workspace_id, self.session_id, self.event_id, self.candidate_id):
            identifier(value)
        for value in (self.candidate_digest, self.protection_digest, self.policy_digest, self.prefix_digest):
            sha256(value)
        for value in (self.observed_sequence, self.project_generation):
            if type(value) is not int or not 0 <= value < 2**63:
                raise ForecastDataError('invalid_recording_generation')


@dataclass(frozen=True)
class Current:
    """Fresh input and selected model version supplied by the source adapter."""
    binding: Binding
    model_digest: str

    def __post_init__(self):
        if type(self.binding) is not Binding:
            raise ForecastDataError('invalid_current_recording_binding')
        sha256(self.model_digest)


@dataclass(frozen=True)
class Request:
    binding: Binding
    prefix: Prefix
    model_digest: str
    created_at: float
    ttl_seconds: float = 30.0
    policy_mode: str = 'enforce'
    horizon: int = 4
    input_scope: str = 'synthetic'
    schema: int = 1

    def __post_init__(self):
        if type(self.binding) is not Binding or type(self.prefix) is not Prefix:
            raise ForecastDataError('invalid_recording_input')
        sha256(self.model_digest)
        if self.binding.prefix_digest != self.prefix.snapshot_digest:
            raise ForecastDataError('recording_prefix_mismatch')
        if (type(self.created_at) not in (int, float) or not math.isfinite(self.created_at) or self.created_at < 0
                or type(self.ttl_seconds) not in (int, float) or not math.isfinite(self.ttl_seconds)
                or not 0 < self.ttl_seconds <= 60):
            raise ForecastDataError('invalid_recording_expiry')
        if (self.policy_mode not in {'observe', 'enforce'} or type(self.horizon) is not int
                or self.horizon not in {1, 2, 4, 8} or self.input_scope not in {'synthetic', 'recorded_structure'}
                or type(self.schema) is not int or self.schema != 1):
            raise ForecastDataError('invalid_recording_condition')
        if len(canonical(asdict(self)).encode()) > MAX_REQUEST_BYTES:
            raise ForecastDataError('recording_request_size_limit')

    @property
    def request_id(self):
        return digest(asdict(self))

    def validity(self, current: Binding, model_digest: str, now: float) -> str:
        if type(current) is not Binding:
            raise ForecastDataError('invalid_current_recording_binding')
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ForecastDataError('invalid_recording_clock')
        if now < self.created_at:
            return 'clock_reversed'
        if now >= self.created_at + self.ttl_seconds:
            return 'expired'
        if model_digest != self.model_digest:
            return 'model_version_changed'
        if self.binding.workspace_id != current.workspace_id:
            return 'different_workspace'
        if self.binding.session_id != current.session_id:
            return 'different_session'
        if self.binding.project_generation != current.project_generation:
            return 'project_generation_changed'
        if self.binding != current:
            return 'input_version_changed'
        return 'current'


def parse_request(value: dict) -> Request:
    """Closed JSON schema; unknown fields cannot carry policy decisions or code."""
    try:
        if type(value) is not dict or set(value) != {f.name for f in fields(Request)}:
            raise ForecastDataError('invalid_recording_request_schema')
        if type(value['binding']) is not dict or set(value['binding']) != {f.name for f in fields(Binding)}:
            raise ForecastDataError('invalid_recording_binding_schema')
        raw = value['prefix']
        if type(raw) is not dict or set(raw) != {f.name for f in fields(Prefix)}:
            raise ForecastDataError('invalid_recording_prefix_schema')
        for key in ('observations', 'objects', 'capabilities', 'protected_sources'):
            if type(raw[key]) is not list:
                raise ForecastDataError('invalid_recording_prefix_array')
        observations = []
        for step in raw['observations']:
            if type(step) is not dict or set(step) != {f.name for f in fields(ObservedStep)}:
                raise ForecastDataError('invalid_recording_step_schema')
            if type(step['inputs']) is not list or type(step['outputs']) is not list:
                raise ForecastDataError('invalid_recording_step_array')
            observations.append(ObservedStep(**{**step, 'inputs': tuple(step['inputs']), 'outputs': tuple(step['outputs'])}))
        objects = []
        for obj in raw['objects']:
            if type(obj) is not dict or set(obj) != {f.name for f in fields(InformationObject)}:
                raise ForecastDataError('invalid_recording_object_schema')
            objects.append(InformationObject(**obj))
        prefix = Prefix(**{**raw, 'observations': tuple(observations), 'objects': tuple(objects),
                           'capabilities': tuple(raw['capabilities']), 'protected_sources': tuple(raw['protected_sources'])})
        return Request(**{**value, 'binding': Binding(**value['binding']), 'prefix': prefix})
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        raise ForecastDataError('invalid_recording_request') from None
