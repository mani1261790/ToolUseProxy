"""Continuation truth is held outside the predictor's visible prefix."""
from __future__ import annotations

from dataclasses import dataclass
import math
import re

from .prefix import ForecastDataError, InformationObject, ObservedStep, Prefix, identifier, sequence


KNOWN_RELATIONS = frozenset({'copy', 'base64', 'save', 'send'})
UNKNOWN_RELATIONS = frozenset({'semantic', 'selection', 'task_boundary', 'unknown'})


@dataclass(frozen=True)
class Transfer:
    source: str
    target: str
    sequence_no: int
    relation: str
    evidence: str  # checked_bytes / receiver / unknown; never detector lineage
    evidence_digest: str | None

    def __post_init__(self):
        identifier(self.source)
        identifier(self.target)
        sequence(self.sequence_no)
        if self.source == self.target:
            raise ForecastDataError('self_transfer')
        if self.relation not in KNOWN_RELATIONS | UNKNOWN_RELATIONS:
            raise ForecastDataError('unknown_relation')
        if self.evidence not in {'checked_bytes', 'receiver', 'unknown'}:
            raise ForecastDataError('invalid_truth_evidence')
        if self.relation in UNKNOWN_RELATIONS and self.evidence != 'unknown':
            raise ForecastDataError('unsupported_truth_relation')
        if self.evidence == 'receiver' and self.relation != 'send':
            raise ForecastDataError('invalid_receiver_relation')
        if self.relation == 'send' and self.evidence == 'checked_bytes':
            raise ForecastDataError('send_requires_receiver_evidence')
        if self.evidence == 'unknown':
            if self.evidence_digest is not None:
                raise ForecastDataError('unknown_evidence_has_digest')
        elif (not isinstance(self.evidence_digest, str)
              or re.fullmatch('[a-f0-9]{64}', self.evidence_digest) is None):
            raise ForecastDataError('missing_truth_evidence')


@dataclass(frozen=True)
class Continuation:
    prefix: Prefix
    branch_id: str
    policy_mode: str
    replay_kind: str
    sampling: str
    probability: float | None
    observations: tuple[ObservedStep, ...]
    objects: tuple[InformationObject, ...]
    transfers: tuple[Transfer, ...]
    protected_sources: tuple[str, ...]
    receiver_arrivals: tuple[tuple[str, int], ...]  # independently confirmed sink/time
    receiver_complete: bool
    termination: str
    control_group: str

    def __post_init__(self):
        if type(self.prefix) is not Prefix:
            raise ForecastDataError('invalid_branch_prefix')
        for value in (self.branch_id, self.control_group):
            identifier(value)
        if self.policy_mode not in {'observe', 'enforce'}:
            raise ForecastDataError('invalid_policy_condition')
        if self.replay_kind not in {'fixed_replay', 'regenerated', 'historical_observation'}:
            raise ForecastDataError('invalid_replay_kind')
        if self.sampling not in {'fixed_distribution', 'adaptive_search'}:
            raise ForecastDataError('invalid_sampling')
        if self.sampling == 'adaptive_search':
            if self.probability is not None:
                raise ForecastDataError('adaptive_frequency_is_not_probability')
        elif (type(self.probability) not in (float, int) or not math.isfinite(self.probability)
              or not 0 < self.probability <= 1):
            raise ForecastDataError('invalid_branch_probability')
        if type(self.receiver_complete) is not bool:
            raise ForecastDataError('invalid_receiver_coverage')
        if self.termination not in {'completed', 'blocked', 'timeout', 'unknown'}:
            raise ForecastDataError('invalid_termination')
        for rows, cls, limit in ((self.observations, ObservedStep, 100),
                                 (self.objects, InformationObject, 256),
                                 (self.transfers, Transfer, 512)):
            if type(rows) is not tuple or len(rows) > limit or any(type(x) is not cls for x in rows):
                raise ForecastDataError('invalid_continuation_records')
        start = self.prefix.max_sequence_no + 1
        if [s.sequence_no for s in self.observations] != list(range(start, start + len(self.observations))):
            raise ForecastDataError('nonsequential_continuation')
        # Reuse visibility validation without ever returning this full view to a predictor.
        full = Prefix(self.prefix.root_case_id, start - 1 + len(self.observations),
                      self.prefix.observations + self.observations,
                      self.prefix.objects + self.objects, self.prefix.capabilities,
                      self.prefix.environment_version, self.prefix.source_version,
                      protected_sources=self.prefix.protected_sources, task_kind=self.prefix.task_kind)
        by_id = {o.object_id: o for o in full.objects}
        if (type(self.protected_sources) is not tuple or not self.protected_sources
                or len(set(self.protected_sources)) != len(self.protected_sources)
                or any(k not in {o.object_id for o in self.prefix.objects if o.kind == 'source'} for k in self.protected_sources)):
            raise ForecastDataError('invalid_protected_sources')
        if self.protected_sources != self.prefix.protected_sources:
            raise ForecastDataError('protection_changed_after_prefix')
        if type(self.receiver_arrivals) is not tuple or len(self.receiver_arrivals) > 100:
            raise ForecastDataError('invalid_receiver_records')
        if len(set(self.receiver_arrivals)) != len(self.receiver_arrivals):
            raise ForecastDataError('duplicate_receiver_record')
        for arrival in self.receiver_arrivals:
            if type(arrival) is not tuple or len(arrival) != 2:
                raise ForecastDataError('invalid_receiver_record')
            key, at = arrival
            sequence(at)
            if (key not in by_id or by_id[key].kind != 'sink'
                    or not start <= at <= full.max_sequence_no or by_id[key].observed_at > at):
                raise ForecastDataError('receiver_outside_continuation')
        for edge in self.transfers:
            if (edge.source not in by_id or edge.target not in by_id
                    or by_id[edge.source].observed_at >= edge.sequence_no
                    or by_id[edge.target].observed_at != edge.sequence_no
                    or not 1 <= edge.sequence_no <= full.max_sequence_no):
                raise ForecastDataError('truth_outside_observation')
            step = full.observations[edge.sequence_no - 1]
            if edge.source not in step.inputs or edge.target not in step.outputs:
                raise ForecastDataError('truth_not_tied_to_operation')
            if edge.evidence == 'receiver' and (edge.target, edge.sequence_no) not in self.receiver_arrivals:
                raise ForecastDataError('receiver_evidence_missing')
