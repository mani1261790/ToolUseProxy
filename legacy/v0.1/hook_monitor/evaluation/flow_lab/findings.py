"""Synthetic failure identities, independent of detector revision and local IDs."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from .agent import Action, Proposal
from .models import Observation, RunSpec, canonical
from .preflight import LabError


FAILURES = ("denial_delivery_conflict", "protected_delivery_after_allow", "unnecessary_stop", "hook_gap")


@dataclass(frozen=True)
class ReplayResult:
    spec: RunSpec
    actions: tuple[Action, ...]
    observations: tuple[Observation, ...]
    causes: tuple[str | None, ...]
    public_control: bool
    protected_control: bool
    environment_profile: str = "docker-fixed-http-v1"
    protected_enforcement: bool | None = None
    cause_traces: tuple = ()

    def __post_init__(self):
        Proposal.parse({"status": "propose", "actions": [asdict(a) for a in self.actions]})
        if len(self.actions) != len(self.observations) or len(self.causes) != len(self.actions):
            raise LabError("incomplete_replay_record")
        if type(self.public_control) is not bool or type(self.protected_control) is not bool:
            raise LabError("invalid_replay_controls")
        if self.protected_enforcement is not None and type(self.protected_enforcement) is not bool:
            raise LabError("invalid_replay_controls")
        if self.environment_profile != "docker-fixed-http-v1":
            raise LabError("unknown_replay_environment")
        if self.cause_traces:
            if len(self.cause_traces) != len(self.actions):
                raise LabError("incomplete_replay_record")
            for trace, cause in zip(self.cause_traces, self.causes):
                if not isinstance(trace, (list, tuple)) or len(trace) > 100:
                    raise LabError("invalid_replay_cause")
                for row in trace:
                    if (not isinstance(row, (list, tuple)) or len(row) != 5
                            or any(not isinstance(v, str) or len(v) > 1024 for v in row)):
                        raise LabError("invalid_replay_cause")
                digest = hashlib.sha256(json.dumps(trace, separators=(",", ":")).encode()).hexdigest() if trace else None
                if digest != cause:
                    raise LabError("invalid_replay_cause")
        elif any(cause is not None for cause in self.causes):
            raise LabError("invalid_replay_cause")
        attempts = set()
        steps = set()
        for number, (action, observation, cause) in enumerate(
            zip(self.actions, self.observations, self.causes), 1
        ):
            if (observation.policy_mode != "enforce" or observation.expected_decision != (
                    "allow" if action.source == "public" else "deny")):
                raise LabError("replay_policy_mismatch")
            if observation.run_id != self.spec.run_id or observation.step_no != number:
                raise LabError("replay_identity_mismatch")
            if observation.step_id in steps:
                raise LabError("replay_identity_mismatch")
            steps.add(observation.step_id)
            attempts.add(observation.attempt_id)
            if cause is not None and (not isinstance(cause, str) or not re.fullmatch(r"[a-f0-9]{64}", cause)):
                raise LabError("invalid_replay_cause")
        if len(attempts) != 1:
            raise LabError("replay_identity_mismatch")

    @property
    def observable(self) -> bool:
        return self.public_control and self.protected_control and all(
            o.observer_state == "complete" and o.receiver_arrival != "unknown"
            and o.environment_denied == "no" and o.hook_delivery in {"observed", "controller_only"}
            and o.termination not in {"no_attempt", "infrastructure_error", "timeout"}
            for o in self.observations
        )


@dataclass(frozen=True)
class FailureSignature:
    kind: str
    action_digest: str
    cause_digest: str | None

    @property
    def key(self) -> str:
        # Revision is observation metadata, never the issue's problem identity.
        return hashlib.sha256(canonical(asdict(self)).encode()).hexdigest()


def failure_signatures(result: ReplayResult) -> tuple[FailureSignature, ...]:
    return tuple(
        FailureSignature(kind, hashlib.sha256(canonical(asdict(action)).encode()).hexdigest(), cause)
        for action, observation, cause in zip(result.actions, result.observations, result.causes)
        for kind in FAILURES if kind in observation.outcomes()
    )
