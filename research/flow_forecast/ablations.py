"""Explicit inference-component removals, not replicas of other published systems."""
from collections import defaultdict
from dataclasses import dataclass, replace

from hook_monitor.evaluation.flow_forecast.predictions import Forecast, Outcome
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from .model import SequenceModel
from .tokens import advance, peers


VARIANTS = ('without_object_identity', 'without_parent_relations', 'without_multistep')


@dataclass(frozen=True)
class Ablation:
    model: SequenceModel
    variant: str

    def __post_init__(self):
        if type(self.model) is not SequenceModel or self.variant not in VARIANTS:
            raise ForecastDataError('unknown_ablation')

    @property
    def version(self):
        return self.variant.replace('_', '-') + '-' + self.model.model_digest[:12]

    def predict(self, prefix, *, policy_mode, horizon):
        if self.variant == 'without_multistep':
            # A one-operation forecast is intentionally not rolled out. The
            # requested horizon is still used by the scorer so missing future
            # edges and arrivals remain visible as failures of this ablation.
            original = self.model.predict(prefix, policy_mode=policy_mode, horizon=1)
            return replace(original, horizon=horizon, model_version=self.version)
        prediction = self.model.generate(prefix, policy_mode=policy_mode, horizon=horizon)
        unknown = prediction.forecast.unknown_probability
        outcomes = defaultdict(float)
        for candidate in prediction.candidates:
            state, unresolved = prefix, False
            for action in candidate.actions:
                if self.variant == 'without_parent_relations' and action.links:
                    unresolved = True
                    break
                if (self.variant == 'without_object_identity'
                        and any(len(peers(state, kind)) > 1 for kind, _ in action.inputs)):
                    unresolved = True
                    break
                state, _ = advance(state, action)
            if unresolved:
                # Removing attribution cannot justify changing an unknown
                # source to an unprotected source or inventing a default parent.
                unknown += candidate.probability
            else:
                outcomes[candidate.routes] += candidate.probability
        items = tuple(Outcome(routes, min(1.0, mass)) for routes, mass in sorted(outcomes.items()))
        other = prediction.forecast.other_probability
        risk = None if unknown + other > 1e-12 else min(1.0, sum(
            item.probability for item in items if any(route.steps[-1][2] == 'sink' for route in item.routes)))
        result = Forecast(prefix.snapshot_digest, policy_mode, horizon, self.version, risk, items,
                          other, min(1.0, unknown))
        result.validate_for(prefix, policy_mode=policy_mode, horizon=horizon)
        return result
