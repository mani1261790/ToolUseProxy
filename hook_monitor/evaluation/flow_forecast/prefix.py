"""Freeze only observations visible at the prediction boundary.

Truth edges, receiver evidence, branch probabilities and detector decisions have
no field in this input contract. They belong to separate continuation records.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


SCHEMA = 1
MAX_STEPS = 100
MAX_OBJECTS = 256
TOOLS = frozenset({'file', 'shell', 'http', 'tool_output'})
OPERATIONS = frozenset({'read', 'copy', 'encode', 'save', 'send', 'branch', 'finish'})
OBJECT_KINDS = frozenset({'source', 'file', 'bytes', 'message', 'sink'})
RESULTS = frozenset({'none', 'ok', 'local', 'send', 'save_then_send', 'unknown'})


class ForecastDataError(ValueError):
    """Closed schema/boundary error, without synthetic or real payloads."""


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value):
    if not isinstance(value, str) or re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', value) is None:
        raise ForecastDataError('invalid_identifier')


def sequence(value, *, zero=False):
    if type(value) is not int or not (0 if zero else 1) <= value <= MAX_STEPS:
        raise ForecastDataError('invalid_sequence')


@dataclass(frozen=True)
class InformationObject:
    object_id: str
    kind: str
    observed_at: int
    version: int = 1

    def __post_init__(self):
        identifier(self.object_id)
        sequence(self.observed_at, zero=True)
        if self.kind not in OBJECT_KINDS or type(self.version) is not int or self.version != 1:
            raise ForecastDataError('invalid_object')


@dataclass(frozen=True)
class ObservedStep:
    sequence_no: int
    tool: str
    operation: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    result: str = 'none'

    def __post_init__(self):
        sequence(self.sequence_no)
        if self.tool not in TOOLS or self.operation not in OPERATIONS or self.result not in RESULTS:
            raise ForecastDataError('invalid_observation')
        for ids in (self.inputs, self.outputs):
            if type(ids) is not tuple or len(ids) > 16 or len(set(ids)) != len(ids):
                raise ForecastDataError('invalid_object_references')
            for value in ids:
                identifier(value)


@dataclass(frozen=True)
class Prefix:
    root_case_id: str
    max_sequence_no: int
    observations: tuple[ObservedStep, ...]
    objects: tuple[InformationObject, ...]
    capabilities: tuple[str, ...]
    environment_version: str
    source_version: str
    schema: int = SCHEMA

    def __post_init__(self):
        for value in (self.root_case_id, self.environment_version, self.source_version):
            identifier(value)
        sequence(self.max_sequence_no, zero=True)
        if type(self.schema) is not int or self.schema != SCHEMA:
            raise ForecastDataError('schema_mismatch')
        if (type(self.observations) is not tuple or type(self.objects) is not tuple
                or len(self.objects) > MAX_OBJECTS or len(self.observations) > MAX_STEPS
                or any(type(x) is not ObservedStep for x in self.observations)
                or any(type(x) is not InformationObject for x in self.objects)):
            raise ForecastDataError('invalid_prefix_records')
        if (type(self.capabilities) is not tuple or not self.capabilities
                or len(set(self.capabilities)) != len(self.capabilities)
                or any(c not in TOOLS for c in self.capabilities)):
            raise ForecastDataError('invalid_capabilities')
        if [s.sequence_no for s in self.observations] != list(range(1, self.max_sequence_no + 1)):
            raise ForecastDataError('missing_or_future_observation')
        by_id = {obj.object_id: obj for obj in self.objects}
        if len(by_id) != len(self.objects):
            raise ForecastDataError('duplicate_object')
        if any(obj.observed_at > self.max_sequence_no for obj in self.objects):
            raise ForecastDataError('future_object_in_prefix')
        introduced = set()
        for step in self.observations:
            if step.tool not in self.capabilities:
                raise ForecastDataError('unavailable_tool')
            for key in (*step.inputs, *step.outputs):
                if key not in by_id or by_id[key].observed_at > step.sequence_no:
                    raise ForecastDataError('unknown_or_future_reference')
            if any(by_id[key].observed_at >= step.sequence_no for key in step.inputs):
                raise ForecastDataError('input_not_yet_visible')
            for key in step.outputs:
                if key in introduced or by_id[key].observed_at != step.sequence_no:
                    raise ForecastDataError('invalid_object_introduction')
                introduced.add(key)
        if introduced != {obj.object_id for obj in self.objects if obj.observed_at > 0}:
            raise ForecastDataError('unobserved_object')

    def model_input(self) -> dict:
        """Fresh JSON value: callers cannot mutate the frozen snapshot through it."""
        return {
            'schema': self.schema, 'max_sequence_no': self.max_sequence_no,
            'observations': [asdict(s) for s in self.observations],
            'objects': [asdict(o) for o in self.objects],
            'capabilities': list(self.capabilities),
            'environment_version': self.environment_version,
            'source_version': self.source_version,
        }

    @property
    def snapshot_digest(self):
        return digest(self.model_input())

    @property
    def prefix_id(self):
        return digest([self.root_case_id, self.snapshot_digest])


def freeze_prefix(*, root_case_id: str, observations: tuple[ObservedStep, ...],
                  objects: tuple[InformationObject, ...], max_sequence_no: int,
                  capabilities: tuple[str, ...], environment_version: str,
                  source_version: str) -> Prefix:
    """Cut a recorder's append-only observations; never rebuild from final truth."""
    sequence(max_sequence_no, zero=True)
    if (type(observations) is not tuple or type(objects) is not tuple
            or len(observations) > MAX_STEPS or len(objects) > MAX_OBJECTS
            or any(type(x) is not ObservedStep for x in observations)
            or any(type(x) is not InformationObject for x in objects)):
        raise ForecastDataError('invalid_prefix_records')
    if [s.sequence_no for s in observations] != list(range(1, len(observations) + 1)):
        raise ForecastDataError('nonsequential_observation')
    return Prefix(
        root_case_id, max_sequence_no,
        tuple(s for s in observations if s.sequence_no <= max_sequence_no),
        tuple(sorted((o for o in objects if o.observed_at <= max_sequence_no),
                     key=lambda o: (o.observed_at, o.object_id))),
        tuple(sorted(capabilities)), environment_version, source_version,
    )
