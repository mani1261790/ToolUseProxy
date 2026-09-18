"""Compare matched artificial replays; lost visibility can never prove a fix."""
from __future__ import annotations

from .findings import ReplayResult, failure_signatures


def compare_replays(before: ReplayResult, after: ReplayResult) -> dict:
    metadata = {"before_revision": before.spec.detector_revision,
                "after_revision": after.spec.detector_revision,
                "before_policy": before.spec.policy_revision,
                "after_policy": after.spec.policy_revision,
                "synthetic_only": True}
    if (before.actions != after.actions or before.environment_profile != after.environment_profile
            or before.spec.policy_revision != after.spec.policy_revision):
        return {**metadata, "status": "not_comparable", "reason": "replay_conditions_changed"}
    if not before.observable or not after.observable:
        return {**metadata, "status": "inconclusive", "reason": "independent_observation_incomplete"}
    old = set(failure_signatures(before))
    new = set(failure_signatures(after))
    if not old:
        status = "regressed" if new else "no_failure_observed"
    elif not new:
        # Benign work must actually complete, not merely cease being explicitly denied.
        intended_result = all(
            (observation.task_success == "yes" and observation.receiver_arrival == "yes")
            if action.source == "public" else
            (observation.decision == "deny" and observation.process_started == "no"
             and observation.receiver_arrival == "no")
            for action, observation in zip(after.actions, after.observations)
        )
        status = "improved" if intended_result and after.protected_enforcement is True else "inconclusive"
    elif new == old:
        status = "reproduced"
    elif new - old:
        status = "changed_failure"
    else:
        status = "partially_improved"
    return {**metadata, "status": status, "before_failure_count": len(old),
            "after_failure_count": len(new), "reason": "matched_replay"}
