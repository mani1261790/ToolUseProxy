"""Frozen small baselines; fitting reads training truth, prediction receives only Prefix."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import math
from types import MappingProxyType

from .dataset import Dataset
from .labels import label_future
from .metrics import truth_routes
from .predictions import Forecast, HORIZONS, Outcome, Route
from .prefix import ForecastDataError, Prefix, digest


KINDS = ('static_reachability', 'frequency', 'risk_only', 'one_step')


def _context(prefix):
    last = prefix.observations[-1] if prefix.observations else None
    return (prefix.task_kind, last.tool if last else 'none', last.operation if last else 'none',
            last.result if last else 'none')


def _lineage(prefix):
    values = {source: {source} for source in prefix.protected_sources}
    for step in prefix.observations:
        if step.operation in {'read', 'copy', 'encode', 'save'}:
            sources = set().union(*(values.get(key, set()) for key in step.inputs))
            for key in step.outputs:
                values[key] = sources
    return values


def _features(prefix, horizon):
    lineage = _lineage(prefix)
    active = any(o.kind != 'source' and lineage.get(o.object_id) for o in prefix.objects)
    last = prefix.observations[-1].result if prefix.observations else 'none'
    return (1.0, float(bool(prefix.protected_sources)), float(active),
            float(prefix.task_kind == 'base64_http'), float(last == 'local'),
            float(last == 'send'), float(last == 'save_then_send'),
            min(prefix.max_sequence_no, 8) / 8, horizon / 8)


def _template(route, prefix):
    objects = {o.object_id: o for o in prefix.objects}
    kind = objects[route.anchor].kind
    peers = [o.object_id for o in prefix.objects if o.kind == kind]
    return (prefix.protected_sources.index(route.source), kind, peers.index(route.anchor), route.steps)


def _instantiate(template, prefix):
    source_index, kind, anchor_index, steps = template
    peers = [o.object_id for o in prefix.objects if o.kind == kind]
    if source_index >= len(prefix.protected_sources) or anchor_index >= len(peers):
        return None
    return Route(prefix.protected_sources[source_index], peers[anchor_index], steps)


def _weighted(rows):
    mass = defaultdict(float)
    for _, root, weight in rows:
        mass[root] += weight
    return [(branch, weight / mass[root] / len(mass)) for branch, root, weight in rows]


def _sigmoid(value):
    if value >= 0:
        return 1 / (1 + math.exp(-min(value, 700)))
    exp = math.exp(max(value, -700))
    return exp / (1 + exp)


@dataclass(frozen=True)
class Baseline:
    kind: str
    training_roots: tuple[str, ...]
    cohorts: dict
    risk_weights: dict
    training_digest: str

    def predict(self, prefix: Prefix, *, policy_mode: str, horizon: int) -> Forecast:
        if type(prefix) is not Prefix or policy_mode not in {'observe', 'enforce'} or type(horizon) is not int or horizon not in HORIZONS:
            raise ForecastDataError('invalid_baseline_input')
        version = self.kind.replace('_', '-') + '-v1-' + self.training_digest[:12]
        def output(p, outcomes=(), other=0.0, unknown=0.0):
            result = Forecast(prefix.snapshot_digest, policy_mode, horizon, version, p,
                              outcomes, other, unknown)
            result.validate_for(prefix, policy_mode=policy_mode, horizon=horizon)
            return result
        if self.kind == 'static_reachability':
            if not prefix.protected_sources or not {'http', 'shell'} & set(prefix.capabilities):
                return output(0.0, (Outcome((), 1.0),))
            if len(prefix.protected_sources) > 16:
                return output(1.0, other=1.0)
            lineage = _lineage(prefix)
            routes = []
            for source in prefix.protected_sources:
                anchors = [o for o in prefix.objects if source in lineage.get(o.object_id, set())]
                anchor = max(anchors, key=lambda o: (o.observed_at, o.object_id)).object_id
                routes.append(Route(source, anchor, ((1, 'send', 'sink'),)))
            return output(1.0, (Outcome(tuple(sorted(routes)), 1.0),))
        trained_horizon = 1 if self.kind == 'one_step' else horizon
        key = (policy_mode, trained_horizon, _context(prefix))
        cohort = self.cohorts.get(key)
        if cohort is None:
            return output(None, unknown=1.0)
        p = None if cohort['unknown_label'] > 1e-12 else min(1.0, max(0.0, cohort['positive']))
        if self.kind == 'risk_only':
            weights = self.risk_weights.get((policy_mode, horizon))
            if p is None or weights is None:
                return output(None, unknown=1.0)
            value = _sigmoid(sum(w * x for w, x in zip(weights, _features(prefix, horizon))))
            return output(value, other=1.0)  # Deliberately produces no path candidates.
        outcomes, other = [], 0.0
        grouped = defaultdict(float)
        for templates, mass in cohort['outcomes'].items():
            routes = tuple(_instantiate(template, prefix) for template in templates)
            if any(route is None for route in routes):
                other += mass
            else:
                grouped[tuple(sorted(routes))] += mass
        ranked = sorted(grouped.items(), key=lambda item: (-item[1], item[0]))
        for routes, mass in ranked[:64]:
            outcomes.append(Outcome(routes, min(1.0, max(0.0, mass))))
        other += sum(mass for _, mass in ranked[64:])
        return output(p, tuple(outcomes), min(1.0, max(0.0, other)),
                      min(1.0, max(0.0, cohort['unknown_path'])))


def fit_baseline(dataset: Dataset, kind: str, *, check_budget=lambda: None) -> Baseline:
    if type(dataset) is not Dataset or kind not in KINDS:
        raise ForecastDataError('unknown_baseline')
    check_budget()
    assignments = {prefix_id: (component, partition) for prefix_id, component, partition in dataset.split.assignments}
    train = [(b, assignments[b.prefix.prefix_id][0], b.probability) for b in dataset.branches
             if assignments[b.prefix.prefix_id][1] == 'train' and b.sampling == 'fixed_distribution']
    roots = tuple(sorted({root for _, root, _ in train}))
    if kind == 'static_reachability':
        return Baseline(kind, (), MappingProxyType({}), MappingProxyType({}), digest([kind, 'v1']))
    if not train:
        raise ForecastDataError('no_fixed_distribution_training_roots')
    grouped, risk_rows = defaultdict(list), defaultdict(list)
    for branch, root, weight in train:
        check_budget()
        for horizon in ((1,) if kind == 'one_step' else HORIZONS):
            grouped[(branch.policy_mode, horizon, _context(branch.prefix))].append((branch, root, weight))
            risk_rows[(branch.policy_mode, horizon)].append((branch, root, weight))
    cohorts = {}
    for key, rows in grouped.items():
        cohort = {'positive': 0.0, 'unknown_label': 0.0, 'unknown_path': 0.0, 'outcomes': defaultdict(float)}
        for branch, weight in _weighted(rows):
            check_budget()
            label = label_future(branch, key[1])
            if label.protected_arrival == 'unknown':
                cohort['unknown_label'] += weight
            elif label.protected_arrival == 'yes':
                cohort['positive'] += weight
            routes = truth_routes(branch, key[1])
            if routes is None:
                cohort['unknown_path'] += weight
            else:
                templates = tuple(sorted(_template(route, branch.prefix) for route in routes))
                cohort['outcomes'][templates] += weight
        cohorts[key] = cohort
    weights_by_condition = {}
    if kind == 'risk_only':
        for key, rows in risk_rows.items():
            known = [(b, root, w) for b, root, w in rows if label_future(b, key[1]).protected_arrival != 'unknown']
            if not known:
                continue
            points = [(_features(b.prefix, key[1]), float(label_future(b, key[1]).protected_arrival == 'yes'), w)
                      for b, w in _weighted(known)]
            weights = [0.0] * 9
            # Fixed deterministic small logistic regression: no tuning on holdout.
            for _ in range(200):
                check_budget()
                gradient = [0.0] * len(weights)
                for features, target, weight in points:
                    error = _sigmoid(sum(w * x for w, x in zip(weights, features))) - target
                    for index, value in enumerate(features):
                        gradient[index] += weight * error * value
                weights = [w - .5 * (g + (.01 * w if index else 0.0))
                           for index, (w, g) in enumerate(zip(weights, gradient))]
            weights_by_condition[key] = tuple(weights)
    frozen = {key: MappingProxyType({**value, 'outcomes': MappingProxyType(dict(value['outcomes']))})
              for key, value in cohorts.items()}
    check_budget()
    training_digest = digest([kind, 'v1', [asdict(b) for b, _, _ in train], roots])
    check_budget()
    return Baseline(kind, roots, MappingProxyType(frozen), MappingProxyType(weights_by_condition), training_digest)
