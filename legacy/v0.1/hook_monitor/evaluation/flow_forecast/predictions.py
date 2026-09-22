"""Bounded joint continuation predictions, separate from observed data."""
from __future__ import annotations

from dataclasses import dataclass
import math
import re

from .branches import KNOWN_RELATIONS
from .calibration import probability
from .prefix import ForecastDataError, Prefix, identifier


HORIZONS = (1, 2, 4, 8)


@dataclass(frozen=True, order=True)
class Route:
    source: str
    anchor: str  # last visible object on this path; future objects are anonymous
    steps: tuple[tuple[int, str, str], ...]  # offset, known relation, future object kind

    def __post_init__(self):
        identifier(self.source)
        identifier(self.anchor)
        if type(self.steps) is not tuple or not 1 <= len(self.steps) <= 8:
            raise ForecastDataError('invalid_predicted_route')
        previous = 0
        for edge in self.steps:
            if type(edge) is not tuple or len(edge) != 3:
                raise ForecastDataError('invalid_predicted_edge')
            offset, relation, kind = edge
            if (type(offset) is not int or not previous < offset <= 8
                    or relation not in KNOWN_RELATIONS or kind not in {'bytes', 'file', 'message', 'sink'}):
                raise ForecastDataError('invalid_predicted_edge')
            if (relation == 'send') != (kind == 'sink'):
                raise ForecastDataError('invalid_predicted_sink')
            previous = offset
        if any(s[2] == 'sink' for s in self.steps[:-1]):
            raise ForecastDataError('route_cannot_continue_after_sink')

    @property
    def shape(self):
        """Topology within the horizon; timing is evaluated separately."""
        return (self.source, self.anchor, tuple((r, k) for _, r, k in self.steps))


@dataclass(frozen=True)
class Outcome:
    routes: tuple[Route, ...]
    probability: float

    def __post_init__(self):
        probability(self.probability)
        if (type(self.routes) is not tuple or len(self.routes) > 16
                or any(type(r) is not Route for r in self.routes)
                or len(set(self.routes)) != len(self.routes)):
            raise ForecastDataError('invalid_joint_outcome')


@dataclass(frozen=True)
class Forecast:
    prefix_digest: str
    policy_mode: str
    horizon: int
    model_version: str
    protected_probability: float | None
    outcomes: tuple[Outcome, ...] = ()
    other_probability: float = 0.0  # predicted but not enumerated continuations
    unknown_probability: float = 0.0  # unresolved future, never counted as safe

    def __post_init__(self):
        if not isinstance(self.prefix_digest, str) or re.fullmatch('[a-f0-9]{64}', self.prefix_digest) is None:
            raise ForecastDataError('invalid_forecast_prefix')
        identifier(self.model_version)
        if self.policy_mode not in {'observe', 'enforce'} or type(self.horizon) is not int or self.horizon not in HORIZONS:
            raise ForecastDataError('invalid_forecast_condition')
        if (type(self.outcomes) is not tuple or len(self.outcomes) > 64
                or any(type(o) is not Outcome for o in self.outcomes)
                or any(r.steps[-1][0] > self.horizon for o in self.outcomes for r in o.routes)):
            raise ForecastDataError('invalid_forecast_outcomes')
        keys = [tuple(sorted(o.routes)) for o in self.outcomes]
        if len(set(keys)) != len(keys):
            raise ForecastDataError('duplicate_joint_outcome')
        probability(self.other_probability)
        probability(self.unknown_probability)
        mass = sum(o.probability for o in self.outcomes) + self.other_probability + self.unknown_probability
        if not math.isclose(mass, 1, rel_tol=0, abs_tol=1e-9):
            raise ForecastDataError('forecast_probability_mass_mismatch')
        if self.protected_probability is not None:
            p = probability(self.protected_probability)
            lower = sum(o.probability for o in self.outcomes
                        if any(route.steps[-1][2] == 'sink' for route in o.routes))
            upper = lower + self.other_probability + self.unknown_probability
            if not lower - 1e-9 <= p <= upper + 1e-9:
                raise ForecastDataError('risk_inconsistent_with_joint_outcomes')

    def validate_for(self, prefix: Prefix, *, policy_mode: str, horizon: int):
        if (self.prefix_digest != prefix.snapshot_digest or self.policy_mode != policy_mode
                or self.horizon != horizon):
            raise ForecastDataError('forecast_context_mismatch')
        visible = {o.object_id for o in prefix.objects}
        if any(r.source not in prefix.protected_sources or r.anchor not in visible
               for outcome in self.outcomes for r in outcome.routes):
            raise ForecastDataError('forecast_references_unknown_source_or_anchor')
