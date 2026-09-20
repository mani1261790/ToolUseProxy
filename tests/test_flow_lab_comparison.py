from dataclasses import replace
import uuid
import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_lab.agent import Action
from hook_monitor.evaluation.flow_lab.compare import compare_replays
from hook_monitor.evaluation.flow_lab.findings import ReplayResult, failure_signatures
from hook_monitor.evaluation.flow_lab.minimize import minimize
from hook_monitor.evaluation.flow_lab.models import Observation, RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError


def result(actions=(Action("public", "plain"),), *, denied=True, cause="a" * 64, revision="old"):
    spec = RunSpec(run_id=uuid.uuid4().hex, suite_version="replay-v1", detector_revision=revision,
                   policy_revision="fixed", environment_digest="b" * 64, started_at=utc_now())
    attempt = uuid.uuid4().hex
    observations = []
    for index, action in enumerate(actions, 1):
        step = uuid.uuid4().hex
        observations.append(Observation(
            run_id=spec.run_id, attempt_id=attempt, step_id=step, tool_use_id=step, step_no=index,
            recorded_at=utc_now(), tool_family="shell", policy_mode="enforce",
            hook_delivery="controller_only", decision="deny" if denied else "allow",
            process_started="no" if denied else "yes", network_attempt="no" if denied else "yes",
            receiver_arrival="no" if denied else "yes",
            protected_arrival="yes" if not denied and action.source != "public" else "no",
            task_success="no" if denied else "yes", environment_denied="no", observer_state="complete",
            evidence_kind="exact", termination="blocked" if denied else "completed",
            expected_decision="allow" if action.source == "public" else "deny",
        ))
    trace = (("block", "critical", "external_http_request", "source_chunk", cause),) if cause else ()
    fingerprint = hashlib.sha256(json.dumps(trace, separators=(",", ":")).encode()).hexdigest() if trace else None
    return ReplayResult(spec, actions, tuple(observations), (fingerprint,) * len(actions), True, True,
                        protected_enforcement=True, cause_traces=(trace,) * len(actions))


def test_public_work_must_really_complete_to_prove_improvement():
    old = result()
    new = result(denied=False, revision="new")
    assert compare_replays(old, new)["status"] == "improved"
    incomplete = replace(new, observations=(replace(new.observations[0], task_success="unknown"),))
    assert compare_replays(old, incomplete)["status"] == "inconclusive"


def test_receiver_failure_can_never_look_like_a_fix():
    old = result((Action("protected", "plain"),), denied=False)
    new = result(old.actions, revision="new")
    assert compare_replays(old, new)["status"] == "improved"
    assert compare_replays(old, replace(new, protected_control=False))["status"] == "inconclusive"
    broken = replace(new, observations=(replace(new.observations[0], receiver_arrival="unknown",
                                               observer_state="failed"),))
    assert compare_replays(old, broken)["status"] == "inconclusive"


def test_same_problem_identity_survives_detector_revision():
    assert failure_signatures(result())[0].key == failure_signatures(result(revision="new"))[0].key


def test_policy_disable_and_changed_inputs_are_not_fixes():
    old = result()
    with pytest.raises(LabError, match="replay_policy_mismatch"):
        replace(old, observations=(replace(old.observations[0], policy_mode="observe"),))
    assert compare_replays(old, result((Action("public", "base64"),)))["status"] == "not_comparable"


def test_unreproduced_finding_and_evidence_are_retained():
    old = result()
    target = failure_signatures(old)[0]
    minimized = minimize(old, target, lambda actions: result(actions, denied=False))
    assert minimized.status == "not_reproduced"
    assert minimized.actions == old.actions
    assert len(minimized.attempts) == 1


def test_minimize_does_not_accept_a_different_cause():
    old = result((Action("public", "base64"), Action("public", "plain")))
    target = failure_signatures(old)[1]
    def replay(actions):
        return result(actions, cause="a" * 64 if len(actions) == 2 else "c" * 64)
    minimized = minimize(old, target, replay)
    assert minimized.actions == old.actions
    assert minimized.replay_count == 3


def test_minimize_removes_only_unneeded_operations_and_is_bounded():
    old = result((Action("public", "base64"), Action("public", "plain")))
    target = failure_signatures(old)[1]
    minimized = minimize(old, target, result, max_replays=2)
    assert minimized.actions == (Action("public", "plain"),)
    assert minimized.replay_count == 2
    limited = minimize(old, target, result, max_replays=1)
    assert limited.status == "budget_exhausted"
    assert limited.actions == old.actions


def test_missing_cause_proof_does_not_authorize_minimization():
    old = result(cause=None)
    minimized = minimize(old, failure_signatures(old)[0], lambda _: pytest.fail("must not replay"))
    assert minimized.status == "cause_unverified"
    assert minimized.replay_count == 0


def test_changed_revision_is_not_same_cause_confirmation():
    old = result()
    minimized = minimize(old, failure_signatures(old)[0], lambda actions: result(actions, revision="new"))
    assert minimized.status == "not_reproduced"


def test_allowing_everything_is_not_an_improvement():
    before = result()
    after = result(denied=False, revision="new")
    assert compare_replays(before, replace(after, protected_enforcement=False))["status"] == "inconclusive"
    assert compare_replays(before, replace(after, protected_enforcement=None))["status"] == "inconclusive"


def test_policy_revision_is_a_fixed_comparison_condition():
    before = result()
    after = result(denied=False, revision="new")
    changed = replace(after, spec=replace(after.spec, policy_revision="changed"))
    assert compare_replays(before, changed)["status"] == "not_comparable"


def test_non_null_cause_requires_matching_trace():
    with pytest.raises(LabError, match="invalid_replay_cause"):
        replace(result(), cause_traces=())


def test_exhaustive_rejection_at_budget_boundary_is_minimized():
    before = result((Action("public", "plain"), Action("protected", "plain")))
    target = failure_signatures(before)[0]
    reduced = minimize(before, target, lambda actions: result(
        actions, cause="a" * 64 if len(actions) == 2 else "c" * 64), max_replays=3)
    assert reduced.actions == before.actions
    assert reduced.replay_count == 3 and reduced.status == "minimized"
