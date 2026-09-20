"""Observed route labels; a stopped or unobserved future is never a safe example."""
from __future__ import annotations

from dataclasses import dataclass

from .branches import Continuation
from .prefix import ForecastDataError


@dataclass(frozen=True)
class Label:
    horizon: int
    protected_arrival: str  # yes / no / unknown
    routes: tuple[tuple[str, ...], ...]
    unknown_edges: int
    censored: bool
    reason: str


def label_future(branch: Continuation, horizon: int) -> Label:
    if type(horizon) is not int or horizon not in {1, 2, 4, 8}:
        raise ForecastDataError('invalid_forecast_horizon')
    end = branch.prefix.max_sequence_no + horizon
    roots = {obj.object_id for obj in branch.prefix.objects if obj.kind == 'source'}
    paths = {key: {(key,)} for key in roots}
    unknown_edges = 0
    for edge in sorted(branch.transfers, key=lambda x: x.sequence_no):
        if edge.sequence_no > end:
            continue
        if edge.evidence == 'unknown':
            unknown_edges += 1
            continue
        for path in tuple(paths.get(edge.source, ())):
            paths.setdefault(edge.target, set()).add((*path, edge.target))
            if sum(len(value) for value in paths.values()) > 1024:
                return Label(horizon, 'unknown', (), unknown_edges, True, 'route_budget_exceeded')
    routes = tuple(sorted({path for sink, at in branch.receiver_arrivals if at <= end
                           for path in paths.get(sink, ()) if path[0] in branch.protected_sources}))
    censored = not branch.receiver_complete or branch.termination != 'completed'
    if routes:
        return Label(horizon, 'yes', routes, unknown_edges, censored, 'independent_route')
    if censored:
        return Label(horizon, 'unknown', (), unknown_edges, True, 'future_not_observed')
    if unknown_edges or any(at <= end and not paths.get(sink)
                            for sink, at in branch.receiver_arrivals):
        return Label(horizon, 'unknown', (), unknown_edges, False, 'path_not_established')
    return Label(horizon, 'no', (), 0, False, 'completed_without_arrival')
