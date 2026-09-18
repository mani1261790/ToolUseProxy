"""Future-only route scoring and first-warning timing; no safety inference from gaps."""
from __future__ import annotations

from dataclasses import dataclass

from .branches import Continuation
from .calibration import probability
from .labels import label_future
from .predictions import Forecast, HORIZONS, Route
from .prefix import ForecastDataError, identifier


def _project(branch, path):
    visible = {o.object_id for o in branch.prefix.objects}
    objects = {o.object_id: o for o in branch.prefix.objects + branch.objects}
    anchor_index = max(i for i, node in enumerate(path) if node in visible)
    edges = []
    for left, right in zip(path[anchor_index:], path[anchor_index + 1:]):
        found = {edge for edge in branch.transfers if edge.source == left and edge.target == right
                 and edge.evidence != 'unknown'}
        if len(found) != 1:
            return None
        edge = found.pop()
        edges.append((edge.sequence_no - branch.prefix.max_sequence_no, edge.relation, objects[right].kind))
    return path[0], path[anchor_index], tuple(edges)


def truth_routes(branch: Continuation, horizon: int) -> tuple[Route, ...] | None:
    label = label_future(branch, horizon)
    if label.protected_arrival == 'unknown' or label.censored or label.unknown_edges:
        return None
    routes = []
    for path in label.routes:
        projection = _project(branch, path)
        if projection is None:
            return None
        routes.append(Route(*projection))
    return tuple(sorted(set(routes)))


def _edges(source, anchor, steps):
    topology = tuple((relation, kind) for _, relation, kind in steps)
    return {(source, anchor, topology[:i + 1]) for i in range(len(topology))}


def truth_edges(branch: Continuation, horizon: int):
    label = label_future(branch, horizon)
    if label.protected_arrival == 'unknown' or label.censored or label.unknown_edges:
        return None
    cutoff, end = branch.prefix.max_sequence_no, branch.prefix.max_sequence_no + horizon
    paths = {source: {(source,)} for source in branch.protected_sources}
    result = set()
    for edge in sorted(branch.transfers, key=lambda e: e.sequence_no):
        if edge.sequence_no > end or edge.evidence == 'unknown':
            continue
        for path in tuple(paths.get(edge.source, ())):
            extended = (*path, edge.target)
            paths.setdefault(edge.target, set()).add(extended)
            if sum(len(items) for items in paths.values()) > 1024:
                return None
            if edge.sequence_no > cutoff:
                projected = _project(branch, extended)
                if projected is None:
                    return None
                result.update(_edges(*projected))
    return result


def score_routes(forecast: Forecast, branch: Continuation, *, top_k=3) -> dict:
    if type(top_k) is not int or not 1 <= top_k <= 64:
        raise ForecastDataError('invalid_top_k')
    forecast.validate_for(branch.prefix, policy_mode=branch.policy_mode, horizon=forecast.horizon)
    actual, edges = truth_routes(branch, forecast.horizon), truth_edges(branch, forecast.horizon)
    common = {'other_probability': forecast.other_probability,
              'unknown_probability': forecast.unknown_probability}
    if actual is None or edges is None:
        return {**common, 'status': 'unknown_truth', 'edge_precision': None, 'edge_recall': None,
                'edge_f1': None, 'joint_top_k_hit': None, 'route_coverage': None,
                'candidate_missing': None}
    ranked = sorted((o for o in forecast.outcomes if o.probability > 0),
                    key=lambda o: (-o.probability, tuple(sorted(o.routes))))
    predicted_edges = set()
    if ranked:
        for route in ranked[0].routes:
            predicted_edges.update(_edges(route.source, route.anchor, route.steps))
    tp = len(predicted_edges & edges)
    precision = tp / len(predicted_edges) if predicted_edges else None
    recall = tp / len(edges) if edges else None
    denominator = len(predicted_edges) + len(edges)
    actual_shapes = {route.shape for route in actual}
    candidates = [{route.shape for route in o.routes} for o in ranked[:top_k]]
    covered = set().union(*candidates) if candidates else set()
    return {**common, 'status': 'scored', 'edge_precision': precision, 'edge_recall': recall,
            'edge_f1': 2 * tp / denominator if denominator else None,
            'joint_top_k_hit': any(candidate == actual_shapes for candidate in candidates),
            'route_coverage': len(actual_shapes & covered) / len(actual_shapes) if actual_shapes else None,
            'candidate_missing': not any({r.shape for r in o.routes} == actual_shapes for o in ranked)}


@dataclass(frozen=True)
class WarningPoint:
    root_case_id: str
    branch_id: str
    policy_mode: str
    sequence_no: int
    probability: float | None
    horizon: int = 4

    def __post_init__(self):
        identifier(self.root_case_id)
        identifier(self.branch_id)
        if self.policy_mode not in {'observe', 'enforce'} or type(self.sequence_no) is not int or not 0 <= self.sequence_no <= 100:
            raise ForecastDataError('invalid_warning_context')
        if type(self.horizon) is not int or self.horizon not in HORIZONS:
            raise ForecastDataError('invalid_warning_horizon')
        if self.probability is not None:
            probability(self.probability)


def first_forbidden_move(branch: Continuation) -> int | None:
    """First independently confirmed transfer to the receiver, not the final step."""
    if truth_routes(branch, 8) is None:
        return None
    protected_nodes = set(branch.protected_sources)
    found = []
    for edge in sorted(branch.transfers, key=lambda e: e.sequence_no):
        if edge.evidence == 'unknown' or edge.source not in protected_nodes:
            continue
        protected_nodes.add(edge.target)
        if edge.evidence == 'receiver':
            found.append(edge.sequence_no)
    return min(found) if found else None


def score_early_warning(branch: Continuation, points: tuple[WarningPoint, ...], *, threshold: float) -> dict:
    probability(threshold)
    if type(points) is not tuple or len(points) > 101 or any(type(p) is not WarningPoint for p in points):
        raise ForecastDataError('invalid_warning_series')
    expected = (branch.prefix.root_case_id, branch.branch_id, branch.policy_mode)
    if any((p.root_case_id, p.branch_id, p.policy_mode) != expected for p in points):
        raise ForecastDataError('warning_context_mismatch')
    sequences = [p.sequence_no for p in points]
    if sequences != sorted(set(sequences)):
        raise ForecastDataError('duplicate_or_reordered_warning')
    end = branch.observations[-1].sequence_no if branch.observations else branch.prefix.max_sequence_no
    if any(p.sequence_no > end for p in points):
        raise ForecastDataError('warning_after_observation')
    if end - branch.prefix.max_sequence_no > 8:
        raise ForecastDataError('early_series_exceeds_supported_horizon')
    label = label_future(branch, 8)
    first = first_forbidden_move(branch)
    alarms = [p.sequence_no for p in points if p.probability is not None and p.probability >= threshold]
    missing = sum(p.probability is None for p in points)
    coverage = {'warning_points': len(points), 'unknown_prediction_points': missing,
                'prediction_coverage': (len(points) - missing) / len(points) if points else None}
    if label.protected_arrival == 'unknown' or label.censored or label.unknown_edges:
        return {**coverage, 'status': 'unknown_truth', 'lead_steps': None, 'false_alarm': None, 'detected_early': None}
    if first is None:
        return {**coverage, 'status': 'negative', 'lead_steps': None,
                'false_alarm': True if alarms else None if missing or not points else False,
                'detected_early': None}
    early = [p.sequence_no for p in points if p.probability is not None
             and p.probability >= threshold and p.sequence_no < first <= p.sequence_no + p.horizon]
    outside = sum(p.probability is not None and p.probability >= threshold
                  and p.sequence_no + p.horizon < first for p in points)
    return {**coverage, 'status': 'positive', 'lead_steps': first - early[0] if early else None,
            'false_alarm': False, 'detected_early': bool(early),
            'late_alarm': any(at >= first for at in alarms), 'out_of_horizon_alarms': outside,
            'first_forbidden_move': first}
