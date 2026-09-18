"""Typed next-operation tokens. Object addresses are relative, never future file names."""
from __future__ import annotations

from dataclasses import dataclass, replace

from hook_monitor.evaluation.flow_forecast.branches import KNOWN_RELATIONS
from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject, ObservedStep, Prefix, OBJECT_KINDS,
    OPERATIONS, RESULTS, TOOLS, canonical,
)


@dataclass(frozen=True, order=True)
class Action:
    tool: str
    operation: str
    result: str
    inputs: tuple[tuple[str, int], ...] = ()
    outputs: tuple[str, ...] = ()
    links: tuple[tuple[int, int, str], ...] = ()

    def __post_init__(self):
        if self.operation in {'end', 'unknown'}:
            if self.tool != 'none' or self.result != 'none' or self.inputs or self.outputs or self.links:
                raise ForecastDataError('invalid_terminal_token')
            return
        if self.tool not in TOOLS or self.operation not in OPERATIONS or self.result not in RESULTS:
            raise ForecastDataError('invalid_action_token')
        if (type(self.inputs) is not tuple or type(self.outputs) is not tuple or type(self.links) is not tuple
                or len(self.inputs) > 16 or len(self.outputs) > 16 or len(self.links) > 256):
            raise ForecastDataError('invalid_action_arity')
        for ref in self.inputs:
            if (type(ref) is not tuple or len(ref) != 2 or ref[0] not in OBJECT_KINDS
                    or type(ref[1]) is not int or not 0 <= ref[1] < 256):
                raise ForecastDataError('invalid_parent_address')
        if len(set(self.inputs)) != len(self.inputs) or any(kind not in OBJECT_KINDS - {'source'} for kind in self.outputs):
            raise ForecastDataError('invalid_action_objects')
        for link in self.links:
            if (type(link) is not tuple or len(link) != 3 or type(link[0]) is not int
                    or type(link[1]) is not int or not 0 <= link[0] < len(self.inputs)
                    or not 0 <= link[1] < len(self.outputs) or link[2] not in KNOWN_RELATIONS):
                raise ForecastDataError('invalid_action_relation')
            if (link[2] == 'send') != (self.outputs[link[1]] == 'sink'):
                raise ForecastDataError('invalid_action_sink')
        if len(set(self.links)) != len(self.links):
            raise ForecastDataError('duplicate_action_relation')


END = Action('none', 'end', 'none')
UNKNOWN = Action('none', 'unknown', 'none')


def peers(prefix, kind):
    # Stable creation order within each kind, newest first. Renaming IDs has no effect.
    return [o.object_id for o in reversed(prefix.objects) if o.kind == kind]


def observed_lineage(prefix):
    lineage = {source: {source} for source in prefix.protected_sources}
    for step in prefix.observations:
        if step.operation in {'read', 'copy', 'encode', 'save', 'send'}:
            parents = set().union(*(lineage.get(key, set()) for key in step.inputs))
            for key in step.outputs:
                lineage[key] = parents
    return lineage


def context(prefix: Prefix, mode: str) -> str:
    """Finite visible state, two previous operations; no truth/branch/root identifiers."""
    objects = {obj.object_id: obj for obj in prefix.objects}
    lineage = observed_lineage(prefix)
    history = []
    for step in prefix.observations[-2:]:
        history.append([step.tool, step.operation, step.result,
                        [[objects[key].kind, bool(lineage.get(key))] for key in step.inputs],
                        [objects[key].kind for key in step.outputs]])
    return canonical([mode, prefix.task_kind, sorted(prefix.capabilities), history])


def encode_action(prefix, step, objects, transfers):
    by_id = {obj.object_id: obj for obj in prefix.objects + objects}
    if step.result == 'unknown':
        return UNKNOWN
    relevant = tuple(edge for edge in transfers if edge.sequence_no == step.sequence_no)
    if any(edge.evidence == 'unknown' for edge in relevant):
        return UNKNOWN
    if set(step.outputs) != {edge.target for edge in relevant}:
        return UNKNOWN  # unsupported creation/causal relation has no invented parent
    refs = tuple((by_id[key].kind, peers(prefix, by_id[key].kind).index(key)) for key in step.inputs)
    return Action(step.tool, step.operation, step.result, refs,
                  tuple(by_id[key].kind for key in step.outputs),
                  tuple(sorted((step.inputs.index(edge.source), step.outputs.index(edge.target), edge.relation)
                               for edge in relevant)))


def advance(prefix, action):
    """Apply a predicted token to an isolated synthetic Prefix, never to any tool."""
    if action.operation in {'end', 'unknown'}:
        raise ForecastDataError('terminal_action_has_no_state')
    if prefix.max_sequence_no >= 100 or len(prefix.objects) + len(action.outputs) > 256:
        raise ForecastDataError('predicted_state_limit')
    inputs = []
    for kind, index in action.inputs:
        candidates = peers(prefix, kind)
        if index >= len(candidates):
            raise ForecastDataError('predicted_parent_unavailable')
        inputs.append(candidates[index])
    at = prefix.max_sequence_no + 1
    occupied = {obj.object_id for obj in prefix.objects}
    outputs = []
    for index, kind in enumerate(action.outputs):
        key = f'forecast-{at}-{index}'
        while key in occupied:
            key += 'x'
        occupied.add(key)
        outputs.append(InformationObject(key, kind, at))
    step = ObservedStep(at, action.tool, action.operation, tuple(inputs),
                        tuple(obj.object_id for obj in outputs), action.result)
    following = replace(prefix, max_sequence_no=at, observations=prefix.observations + (step,),
                        objects=prefix.objects + tuple(outputs))
    links = tuple((inputs[left], outputs[right].object_id, relation)
                  for left, right, relation in action.links)
    return following, links
