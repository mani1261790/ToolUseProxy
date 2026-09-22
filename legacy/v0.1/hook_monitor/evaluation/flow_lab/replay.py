"""Fresh, bounded synthetic replay with durable pre-dispatch evidence.

Every case owns a new receiver/network. A pending case is retained and never
silently dispatched again after interruption. No model or runtime DB is used.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import math
from pathlib import Path
import time
import uuid

from .adaptive_transport import AdaptiveTransport
from .agent import Action, Proposal
from .controller import execute_action
from .findings import ReplayResult
from .models import Observation, RunSpec, utc_now
from .preflight import LabError, build_context, build_image, check_isolation
from .runner import Scenario, run_scenario
from .revision import implementation_revision
from .search_state import SearchJournal
from .storage import TrialStore


MAX_STORAGE = 1024 * 1024 * 1024


def decode_result(value: dict) -> ReplayResult:
    try:
        return ReplayResult(
            RunSpec(**value["spec"]), tuple(Action(**a) for a in value["actions"]),
            tuple(Observation(**o) for o in value["observations"]), tuple(value["causes"]),
            value["public_control"], value["protected_control"], value["environment_profile"],
            value.get("protected_enforcement"),
            tuple(tuple(tuple(row) for row in trace) for trace in value.get("cause_traces", ())),
        )
    except (KeyError, TypeError, ValueError):
        raise LabError("invalid_replay_record") from None


class ReplayCampaign:
    """At most five cases (20 attempts including receiver and enforcement controls)."""

    def __init__(self, directory: Path, *, max_replays=5, seconds=600, clock=time.time):
        if type(max_replays) is not int or not 1 <= max_replays <= 5:
            raise LabError("invalid_replay_budget")
        if type(seconds) is not int or not 1 <= seconds <= 1800:
            raise LabError("invalid_replay_budget")
        self.directory = directory
        self.limit = max_replays
        self.seconds = seconds
        self.clock = clock
        self.stack = ExitStack()

    def __enter__(self):
        try:
            self.journal = self.stack.enter_context(SearchJournal(self.directory))
            self.stack.enter_context(self.journal.lease())
            self.store = self.stack.enter_context(TrialStore(self.directory / "trials"))
            self.state = self.journal.read()
            identity = {"kind": "synthetic-replay-v1", "max_replays": self.limit,
                        "seconds": self.seconds, "controller_revision": implementation_revision()}
            if self.state is None:
                self.state = {"identity": identity, "started": self.clock(), "cases": []}
                self.journal.write(self.state)
            if (self.state.get("identity") != identity
                    or not isinstance(self.state.get("cases"), list)
                    or len(self.state["cases"]) > self.limit
                    or type(self.state.get("started")) not in (int, float)
                    or not math.isfinite(self.state["started"])):
                raise LabError("replay_campaign_mismatch")
            for case in self.state["cases"]:
                if not isinstance(case, dict) or case.get("status") not in {"pending", "completed"}:
                    raise LabError("invalid_replay_record")
                if case["status"] == "completed":
                    result = decode_result(case["result"])
                    if (result.spec.run_id != case.get("run_id")
                            or result.spec.detector_revision != case.get("detector_revision")
                            or [asdict(a) for a in result.actions] != case.get("actions")):
                        raise LabError("invalid_replay_record")
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *_):
        self.stack.close()

    @property
    def results(self):
        return tuple(decode_result(case["result"]) for case in self.state["cases"]
                     if case["status"] == "completed")

    def check_budget(self):
        if self.clock() - self.state["started"] >= self.seconds:
            raise LabError("replay_time_budget_exhausted")
        if self.journal.storage_size() >= MAX_STORAGE:
            raise LabError("replay_storage_budget_exhausted")

    def run(self, repository: Path, actions: tuple[Action, ...], *, expected_revision=None) -> ReplayResult:
        Proposal.parse({"status": "propose", "actions": [asdict(a) for a in actions]})
        if any(case["status"] == "pending" for case in self.state["cases"]):
            raise LabError("replay_requires_reconciliation")
        self.store.require_no_unfinished_runs()
        if len(self.state["cases"]) >= self.limit:
            raise LabError("replay_budget_exhausted")
        self.check_budget()
        # Closed source-only context excludes all user data and the root manifest.
        context = build_context(repository)
        revision = "source-" + hashlib.sha256(context).hexdigest()
        if expected_revision is not None and revision != expected_revision:
            raise LabError("replay_source_changed")
        case = {"status": "pending", "detector_revision": revision,
                "actions": [asdict(a) for a in actions], "run_id": uuid.uuid4().hex}
        self.state["cases"].append(case)
        self.journal.write(self.state)  # charge a case before any Docker operation
        # Pin the first verified image for each source revision. Rebuilding identical
        # source can produce a different Docker image identity (build timestamps).
        # Reproduction requires the exact previous image, not a silently rebuilt one.
        previous = next((r for r in self.results if r.spec.detector_revision == revision), None)
        image = ("sha256:" + previous.spec.environment_digest if previous else
                 build_image(repository, context=context))
        check_isolation(image)
        self.check_budget()
        spec = RunSpec(case["run_id"], "fresh-replay-v1", revision,
                       "fixed-exact-externality-v1", image[7:], utc_now(), max_trials=4)
        self.store.start(spec)
        with AdaptiveTransport(image) as transport:
            controls = []
            for source in ("public", "protected"):
                self.check_budget()
                controls.append(run_scenario(transport, self.store, spec,
                                             Scenario(source, "observe", "http_inline")))
            public_ok = (controls[0].receiver_arrival == "yes"
                         and controls[0].protected_arrival == "no"
                         and controls[0].task_success == "yes")
            protected_ok = (controls[1].receiver_arrival == "yes"
                            and controls[1].protected_arrival == "yes")
            self.check_budget()
            enforcement = run_scenario(transport, self.store, spec,
                                       Scenario("protected", "enforce", "http_inline"))
            protected_enforcement = (enforcement.decision == "deny"
                                     and enforcement.process_started == "no"
                                     and enforcement.receiver_arrival == "no"
                                     and enforcement.observer_state == "complete")
            observations, causes, traces = [], [], []
            attempt = uuid.uuid4().hex
            for number, action in enumerate(actions, 1):
                self.check_budget()
                step = uuid.uuid4().hex
                observations.append(execute_action(transport, self.store, spec,
                                                   action, attempt, step, number))
                causes.append(transport.guard_causes.get(step))
                traces.append(transport.guard_traces.get(step, ()))
            result = ReplayResult(spec, actions, tuple(observations), tuple(causes),
                                  public_ok, protected_ok, protected_enforcement=protected_enforcement,
                                  cause_traces=tuple(traces))
        # Cleanup must finish before completion is recorded. Incomplete evidence stays pending.
        self.store.finish(spec, utc_now())
        case.update(status="completed", result=asdict(result))
        self.journal.write(self.state)
        return result
