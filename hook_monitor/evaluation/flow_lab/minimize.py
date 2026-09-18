"""Budgeted deletion minimization with fresh replay and cause-preservation checks."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .agent import Action
from .findings import FailureSignature, ReplayResult, failure_signatures
from .preflight import LabError


@dataclass(frozen=True)
class Minimized:
    actions: tuple[Action, ...]
    status: str
    replay_count: int
    attempts: tuple[ReplayResult, ...]


def minimize(original: ReplayResult, target: FailureSignature,
             replay: Callable[[tuple[Action, ...]], ReplayResult], *, max_replays: int = 10) -> Minimized:
    if type(max_replays) is not int or not 1 <= max_replays <= 20:
        raise LabError("invalid_replay_budget")
    if target not in failure_signatures(original):
        raise LabError("failure_not_in_original")
    if not original.observable or target.cause_digest is None:
        return Minimized(original.actions, "cause_unverified", 0, ())
    def same_conditions(result):
        return (result.spec.detector_revision == original.spec.detector_revision
                and result.spec.policy_revision == original.spec.policy_revision
                and result.spec.environment_digest == original.spec.environment_digest
                and result.environment_profile == original.environment_profile)

    attempts = []
    confirmation = replay(original.actions)
    attempts.append(confirmation)
    if (not same_conditions(confirmation) or not confirmation.observable or confirmation.actions != original.actions
            or target not in failure_signatures(confirmation)):
        return Minimized(original.actions, "not_reproduced", 1, tuple(attempts))
    best = original.actions
    index = 0
    while len(best) > 1 and index < len(best) and len(attempts) < max_replays:
        candidate = best[:index] + best[index+1:]
        result = replay(candidate)
        attempts.append(result)
        if (same_conditions(result) and result.actions == candidate and result.observable
                and target in failure_signatures(result)):
            best = candidate
            index = 0
        else:
            index += 1
    status = "budget_exhausted" if len(attempts) == max_replays and len(best) > 1 else "minimized"
    return Minimized(best, status, len(attempts), tuple(attempts))
