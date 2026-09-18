"""Small categorical operation-sequence model with bounded joint graph rollouts."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field, replace
import hashlib
import math
from pathlib import Path
import re
from types import MappingProxyType

from hook_monitor.evaluation.flow_forecast.dataset import Dataset
from hook_monitor.evaluation.flow_forecast.predictions import Forecast, HORIZONS, Outcome, Route
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, Prefix, digest, identifier
from .tokens import Action, END, UNKNOWN, advance, context, encode_action, observed_lineage


ALGORITHM = 'typed-operation-markov-v1'
# Pin the small inference implementation and its data contracts, not the checkout
# or user configuration. Read only this explicit list of source files.
_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_FILES = (
    'research/flow_forecast/model.py', 'research/flow_forecast/tokens.py',
    'hook_monitor/evaluation/flow_forecast/prefix.py',
    'hook_monitor/evaluation/flow_forecast/branches.py',
    'hook_monitor/evaluation/flow_forecast/predictions.py',
    'hook_monitor/evaluation/flow_forecast/calibration.py',
)
IMPLEMENTATION_SHA256 = hashlib.sha256(b''.join(
    name.encode() + b'\0' + (_SOURCE_ROOT / name).read_bytes() + b'\0' for name in _SOURCE_FILES
)).hexdigest()
MAX_CONTEXTS = 4096
MAX_CHOICES = 128
MAX_BEAM = 64
MAX_EXPANSIONS = 8192
CONFIGURATION = MappingProxyType({
    'context_operations': 2, 'estimator': 'root_balanced_categorical', 'smoothing': 'none',
    'default_beam_width': MAX_BEAM, 'maximum_expansions': MAX_EXPANSIONS,
    'maximum_contexts': MAX_CONTEXTS, 'maximum_actions_per_context': MAX_CHOICES,
    'maximum_horizon': 8, 'maximum_paths_per_state': 1024,
})


@dataclass(frozen=True)
class Candidate:
    probability: float
    actions: tuple[Action, ...]
    routes: tuple[Route, ...]
    terminal: bool


@dataclass(frozen=True)
class Prediction:
    forecast: Forecast
    candidates: tuple[Candidate, ...]
    expansions: int
    beam_width: int


def _routes(paths):
    found = {Route(source, anchor, steps) for values in paths.values()
             for source, anchor, steps in values if steps}
    # Keep maximal paths; their edge sets also include every intermediate object.
    return tuple(sorted(path for path in found if not any(
        path.source == other.source and path.anchor == other.anchor
        and len(path.steps) < len(other.steps) and other.steps[:len(path.steps)] == path.steps
        for other in found)))


def _initial_paths(prefix):
    return {key: tuple((source, key, ()) for source in sorted(sources))
            for key, sources in observed_lineage(prefix).items()}


def _extend(paths, links, following, cutoff):
    copied = dict(paths)
    kinds = {obj.object_id: obj.kind for obj in following.objects}
    for left, right, relation in links:
        new = {(source, anchor, (*steps, (following.max_sequence_no - cutoff, relation, kinds[right])))
               for source, anchor, steps in paths.get(left, ())}
        copied[right] = tuple(sorted(set(copied.get(right, ())) | new))
    if sum(len(values) for values in copied.values()) > 1024:
        raise ForecastDataError('predicted_path_limit')
    return copied


@dataclass(frozen=True)
class SequenceModel:
    transitions: dict
    training_digest: str
    training_roots: tuple[str, ...]
    algorithm: str = ALGORITHM
    model_digest: str = field(init=False)

    def __post_init__(self):
        if (self.algorithm != ALGORITHM or type(self.training_digest) is not str
                or re.fullmatch('[a-f0-9]{64}', self.training_digest) is None
                or type(self.training_roots) is not tuple or not 1 <= len(self.training_roots) <= 10000
                or tuple(sorted(set(self.training_roots))) != self.training_roots
                or not isinstance(self.transitions, (dict, MappingProxyType))
                or not 1 <= len(self.transitions) <= MAX_CONTEXTS):
            raise ForecastDataError('invalid_sequence_model')
        for root in self.training_roots:
            identifier(root)
        for key, choices in self.transitions.items():
            if (type(key) is not str or len(key) > 16384 or type(choices) is not tuple
                    or not 1 <= len(choices) <= MAX_CHOICES):
                raise ForecastDataError('invalid_model_context')
            actions = set()
            mass = 0.0
            for row in choices:
                if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not Action
                        or type(row[1]) not in (float, int) or not math.isfinite(row[1])
                        or not 0 < row[1] <= 1 or row[0] in actions):
                    raise ForecastDataError('invalid_model_distribution')
                actions.add(row[0])
                mass += row[1]
            if not math.isclose(mass, 1, rel_tol=0, abs_tol=1e-9):
                raise ForecastDataError('invalid_model_probability_mass')
        object.__setattr__(self, 'transitions', MappingProxyType(dict(self.transitions)))
        object.__setattr__(self, 'model_digest', digest(self.payload()))

    def payload(self):
        return {'schema': 1, 'algorithm': self.algorithm, 'configuration': dict(CONFIGURATION),
                'implementation_sha256': IMPLEMENTATION_SHA256,
                'training_digest': self.training_digest,
                'training_roots': list(self.training_roots),
                'transitions': [[key, [[asdict(action), probability] for action, probability in choices]]
                                for key, choices in sorted(self.transitions.items())]}

    @property
    def version(self):
        return self.algorithm + '-' + self.model_digest[:12]

    def predict(self, prefix: Prefix, *, policy_mode: str, horizon: int) -> Forecast:
        return self.generate(prefix, policy_mode=policy_mode, horizon=horizon).forecast

    def generate(self, prefix: Prefix, *, policy_mode: str, horizon: int, beam_width=64) -> Prediction:
        if (type(prefix) is not Prefix or policy_mode not in {'observe', 'enforce'}
                or type(horizon) is not int or horizon not in HORIZONS
                or type(beam_width) is not int or not 1 <= beam_width <= MAX_BEAM):
            raise ForecastDataError('invalid_sequence_prediction_request')
        # state: joint probability, isolated visible state, predicted paths, emitted tokens
        active = [(1.0, prefix, _initial_paths(prefix), ())]
        finished, unknown, other, expansions = [], 0.0, 0.0, 0
        for depth in range(horizon + 1):
            next_states = []
            for mass, state, paths, actions in active:
                if depth == horizon:
                    try:
                        routes = _routes(paths)
                        if len(routes) > 16:
                            raise ForecastDataError('predicted_route_limit')
                        finished.append(Candidate(mass, actions, routes, False))
                    except ForecastDataError:
                        unknown += mass
                    continue
                choices = self.transitions.get(context(state, policy_mode), ((UNKNOWN, 1.0),))
                for action, probability in choices:
                    joint = mass * probability
                    if joint == 0:
                        continue
                    if expansions >= MAX_EXPANSIONS:
                        other += joint
                        continue
                    expansions += 1
                    if action == UNKNOWN:
                        unknown += joint
                        continue
                    try:
                        if action == END:
                            routes = _routes(paths)
                            if len(routes) > 16:
                                raise ForecastDataError('predicted_route_limit')
                            finished.append(Candidate(joint, actions, routes, True))
                        else:
                            following, links = advance(state, action)
                            next_paths = _extend(paths, links, following, prefix.max_sequence_no)
                            next_states.append((joint, following, next_paths, (*actions, action)))
                            if len(next_states) > 2 * beam_width:
                                next_states.sort(key=lambda row: (-row[0], row[3]))
                                other += math.fsum(row[0] for row in next_states[beam_width:])
                                next_states = next_states[:beam_width]
                    except ForecastDataError:
                        unknown += joint  # unsupported state is not a safe continuation
            next_states.sort(key=lambda row: (-row[0], row[3]))
            other += math.fsum(row[0] for row in next_states[beam_width:])
            active = next_states[:beam_width]
            # Terminal candidates also consume the bounded enumeration budget.
            finished.sort(key=lambda c: (-c.probability, c.actions))
            other += math.fsum(c.probability for c in finished[beam_width:])
            finished = finished[:beam_width]
        joint_routes = defaultdict(float)
        for candidate in finished:
            joint_routes[candidate.routes] += candidate.probability
        outcomes = tuple(Outcome(routes, min(1.0, mass)) for routes, mass in sorted(joint_routes.items()))
        arrived = math.fsum(o.probability for o in outcomes if any(r.steps[-1][2] == 'sink' for r in o.routes))
        risk = min(1.0, arrived) if unknown + other < 1e-12 else None
        forecast = Forecast(prefix.snapshot_digest, policy_mode, horizon, self.version, risk, outcomes,
                            min(1.0, max(0.0, other)), min(1.0, max(0.0, unknown)))
        forecast.validate_for(prefix, policy_mode=policy_mode, horizon=horizon)
        return Prediction(forecast, tuple(finished), expansions, beam_width)


def fit(dataset: Dataset, *, check_budget=None) -> SequenceModel:
    if type(dataset) is not Dataset:
        raise ForecastDataError('invalid_training_dataset')
    assignments = {prefix: (root, part) for prefix, root, part in dataset.split.assignments}
    train = [(b, assignments[b.prefix.prefix_id][0]) for b in dataset.branches
             if assignments[b.prefix.prefix_id][1] == 'train' and b.sampling == 'fixed_distribution']
    if not train:
        raise ForecastDataError('no_fixed_distribution_training_roots')
    # Each root contributes equal total mass within a context. Prefix variants
    # never become independent training roots or independent confidence samples.
    counts = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for branch, root in train:
        if check_budget is not None:
            check_budget()
        state = branch.prefix
        unknown = False
        for step in branch.observations:
            action = encode_action(state, step, branch.objects, branch.transfers)
            key = context(state, branch.policy_mode)
            counts[key][root][action] += branch.probability
            if len(counts) > MAX_CONTEXTS:
                raise ForecastDataError('model_context_limit')
            if action == UNKNOWN:
                unknown = True
                break
            # Teacher forcing uses only the newly observed step at each boundary.
            additions = tuple(obj for obj in branch.objects if obj.observed_at == step.sequence_no)
            state = replace(state, max_sequence_no=step.sequence_no,
                            observations=state.observations + (step,), objects=state.objects + additions)
        if not unknown:
            terminal = END if branch.termination == 'completed' and branch.receiver_complete else UNKNOWN
            counts[context(state, branch.policy_mode)][root][terminal] += branch.probability
        if len(counts) > MAX_CONTEXTS:
            raise ForecastDataError('model_context_limit')
    transitions = {}
    for key, roots in sorted(counts.items()):
        if check_budget is not None:
            check_budget()
        probabilities = defaultdict(float)
        for values in roots.values():
            total = math.fsum(values.values())
            for action, count in values.items():
                probabilities[action] += count / total / len(roots)
        if len(probabilities) > MAX_CHOICES:
            raise ForecastDataError('model_action_limit')
        transitions[key] = tuple(sorted(probabilities.items()))
    roots = tuple(sorted({root for _, root in train}))
    training_digest = digest([ALGORITHM, [asdict(b) for b, _ in train], roots])
    return SequenceModel(MappingProxyType(transitions), training_digest, roots)
