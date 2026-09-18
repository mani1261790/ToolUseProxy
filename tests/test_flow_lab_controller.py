from dataclasses import replace
import uuid

import pytest

from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.budget import Budget
from hook_monitor.evaluation.flow_lab.controller import run_search
from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
from hook_monitor.evaluation.flow_lab.storage import TrialStore


def proposal(source="protected", encoding="plain"):
    return {"status": "propose", "actions": [{"source": source, "encoding": encoding}]}


class Provider:
    model_id = "synthetic-fixture"

    def __init__(self, values):
        self.values = iter(values)
        self.feedback = []

    def propose(self, feedback, **limits):
        self.feedback.append(feedback)
        value = next(self.values)
        if isinstance(value, BaseException):
            raise value
        return value


class Transport:
    def __init__(self):
        self.sent = 0
        self.guards = 0
        self.fail = False

    def prepare(self, step_id, **kwargs):
        return "synthetic-command"

    def guard(self, *args, **kwargs):
        self.guards += 1
        if self.fail:
            raise LabError("guard_receipt_missing")
        return "deny"

    def send(self, *args):
        self.sent += 1
        return True

    def delivery(self, step_id):
        return "no", "no"


@pytest.fixture
def context(tmp_path):
    budget = Budget()
    spec = RunSpec(run_id=uuid.uuid4().hex, suite_version="adaptive-v1",
                   detector_revision="fixture", policy_revision="fixture",
                   environment_digest="a" * 64, started_at=utc_now(), mode="adaptive_search")
    with SearchJournal(tmp_path / "search") as journal:
        with TrialStore(journal.directory / "trials") as store:
            yield journal, store, spec, Transport(), budget


def run(context, provider, **kwargs):
    journal, store, spec, transport, budget = context
    return run_search(journal, store, spec, transport, provider, budget, **kwargs)


def test_adapts_after_denial_and_finishes(context):
    provider = Provider([proposal(), proposal(encoding="base64"), {"status": "complete", "actions": []}])
    result = run(context, provider)
    assert result["status"] == "completed"
    assert result["summary"]["observation_count"] == 2
    assert provider.feedback[1][0]["decision"] == "deny"
    assert context[3].sent == 0
    assert context[1].summary(context[2])["state"] == "complete"


@pytest.mark.parametrize("value", [
    {"status": "propose", "actions": [], "sudo": True},
    {"status": "propose", "actions": [{"command": "sudo echo private"}]},
    proposal("/real/path"), proposal(encoding="arbitrary-script"),
    {"status": "complete", "actions": [{"source": "public", "encoding": "plain"}]},
])
def test_rejects_authority_or_arbitrary_commands(context, value):
    assert run(context, Provider([value]))["status"] == "invalid_model_proposal"
    assert context[3].guards == context[3].sent == 0


def test_repeated_plan_stops_without_second_dispatch(context):
    assert run(context, Provider([proposal(), proposal()]))["status"] == "repeated_proposal"
    assert context[3].guards == 1


@pytest.mark.parametrize("reason", ["model_auth_required", "model_quota_exhausted", "model_timeout"])
def test_failure_is_charged_and_can_resume(context, reason):
    assert run(context, Provider([LabError(reason)]))["status"] == reason
    assert context[0].read()["calls"] == 1
    result = run(context, Provider([proposal(), {"status": "complete", "actions": []}]))
    assert result["status"] == "completed"
    assert context[0].read()["calls"] == 3


def test_interrupted_model_call_is_not_silently_repeated(context):
    with pytest.raises(KeyboardInterrupt):
        run(context, Provider([KeyboardInterrupt()]))
    assert run(context, Provider([]))["status"] == "model_response_unknown"
    assert context[0].read()["calls"] == 1


def test_pending_dispatch_is_not_repeated_after_restart(context):
    context[3].fail = True
    with pytest.raises(LabError, match="guard_receipt_missing"):
        run(context, Provider([proposal()]))
    context[3].fail = False
    assert run(context, Provider([]))["status"] == "operation_requires_reconciliation"
    assert context[3].guards == 1
    assert len(context[1].pending(context[2])) == 1


def test_resume_after_observation_never_repeats_completed_step(context, monkeypatch):
    original = context[0].write
    def fail_on_second_request(state):
        if state["calls"] == 2:
            raise KeyboardInterrupt
        original(state)
    monkeypatch.setattr(context[0], "write", fail_on_second_request)
    with pytest.raises(KeyboardInterrupt):
        run(context, Provider([proposal()]))
    monkeypatch.setattr(context[0], "write", original)
    result = run(context, Provider([{"status": "complete", "actions": []}]))
    assert result["status"] == "completed"
    assert context[3].guards == 1


def test_budget_stops_before_model_call(context):
    limited = replace(context[-1], model_calls=1)
    result = run((*context[:-1], limited), Provider([proposal()]))
    assert result["status"] == "model_budget_exhausted"
    assert context[3].guards == 1


def test_trial_budget_stops(context):
    budget = replace(context[-1], trials=1)
    spec = replace(context[2], max_trials=1)
    result = run((context[0], context[1], spec, context[3], budget), Provider([proposal()]))
    assert result["status"] == "trial_budget_exhausted"


def test_wallclock_budget_includes_interruption(context):
    assert run(context, Provider([LabError("model_auth_required")]), clock=lambda: 100)["status"]
    result = run(context, Provider([]), clock=lambda: 2000)
    assert result["status"] == "time_budget_exhausted"


def test_only_one_controller(context):
    with context[0].lease():
        with pytest.raises(LabError, match="search_already_running"):
            run(context, Provider([]))


def test_unrelated_directory_rejected(tmp_path):
    (tmp_path / "user.txt").write_text("kept")
    with pytest.raises(LabError, match="unrelated_search_storage"):
        SearchJournal(tmp_path)
    assert (tmp_path / "user.txt").read_text() == "kept"


def test_proposal_schema_does_not_accept_missing_or_unbounded_actions():
    with pytest.raises(LabError):
        Proposal.parse({"status": "propose", "actions": proposal()["actions"] * 11})
    with pytest.raises(LabError):
        Proposal.parse({})


def test_terminal_checkpoint_finishes_run_after_crash(context, monkeypatch):
    original = context[1].finish
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(context[1], "finish", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run(context, Provider([{"status": "complete", "actions": []}]))
    monkeypatch.setattr(context[1], "finish", original)
    result = run(context, Provider([]))
    assert result["status"] == "completed"
    assert result["summary"]["state"] == "complete"


@pytest.mark.parametrize("key,value", [("calls", -1), ("calls", True), ("plans", {}),
                                       ("started", "not-a-time"), ("phase", "sudo")])
def test_corrupt_checkpoint_is_refused(context, key, value):
    run(context, Provider([LabError("model_auth_required")]))
    state = context[0].read()
    state[key] = value
    context[0].write(state)
    with pytest.raises(LabError, match="invalid_search_state"):
        run(context, Provider([]))
    assert context[3].guards == 0
