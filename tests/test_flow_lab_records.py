from __future__ import annotations

from dataclasses import asdict, replace
import json
import sqlite3
import uuid

import pytest

from hook_monitor.evaluation.flow_lab.models import Observation, RecordError, RunSpec, from_mapping
from hook_monitor.evaluation.flow_lab.storage import StoreError, TrialStore


def spec(**changes) -> RunSpec:
    return replace(RunSpec(
        run_id=uuid.uuid4().hex, suite_version="fixture-v1", detector_revision="alpha15",
        policy_revision="lab-v1", environment_digest="a" * 64,
        started_at="2026-09-06T01:00:00Z",
    ), **changes)


def observed(run, **changes) -> Observation:
    return replace(Observation(
        run_id=run.run_id, attempt_id=uuid.uuid4().hex, step_id=uuid.uuid4().hex,
        tool_use_id=uuid.uuid4().hex, step_no=1, recorded_at="2026-09-06T01:01:00Z",
        tool_family="http", policy_mode="enforce", hook_delivery="controller_only",
        decision="allow", process_started="yes", network_attempt="yes",
        receiver_arrival="yes", protected_arrival="no", task_success="yes",
        environment_denied="no", observer_state="complete", evidence_kind="exact",
        termination="completed",
    ), **changes)


def test_no_arrival_alone_is_not_success() -> None:
    o = observed(spec(), receiver_arrival="no", task_success="unknown")
    assert o.outcomes() == ()
    assert "environment_denial" in replace(o, environment_denied="yes").outcomes()
    assert "incomplete_observation" in replace(o, observer_state="failed").outcomes()
    assert "not_tested" in replace(o, termination="no_attempt").outcomes()


def test_denial_and_arrival_are_retained_as_conflict() -> None:
    o = observed(spec(), decision="deny", protected_arrival="yes")
    assert "protected_delivery" in o.outcomes()
    assert "denial_delivery_conflict" in o.outcomes()
    assert "denial_delivery_conflict" not in replace(o, policy_mode="observe").outcomes()


@pytest.mark.parametrize("changes", [
    {"protected_arrival": "yes", "receiver_arrival": "no"},
    {"protected_arrival": "yes", "evidence_kind": "unverified"},
    {"network_attempt": False}, {"decision": "PRIVATE_COMMAND"}, {"step_no": True},
    {"step_no": 0}, {"schema_version": 2}, {"schema_version": True},
    {"recorded_at": "2026-09-06T01:00:00"}, {"recorded_at": "invalidZ"},
    {"run_id": "/private/path"},
])
def test_invalid_observations_rejected(changes) -> None:
    with pytest.raises(RecordError):
        observed(spec(), **changes)


@pytest.mark.parametrize("changes", [
    {"max_trials": 0}, {"max_trials": True}, {"max_steps": 1001},
    {"mode": "pilot"}, {"schema_version": 2}, {"environment_digest": "unknown"},
    {"detector_revision": "https://private.invalid"},
])
def test_invalid_runs_rejected(changes) -> None:
    with pytest.raises(RecordError):
        spec(**changes)


def test_raw_fields_and_missing_fields_are_not_accepted() -> None:
    value = asdict(observed(spec()))
    assert from_mapping(Observation, value).step_no == 1
    with pytest.raises(RecordError, match="record_shape_mismatch"):
        from_mapping(Observation, {**value, "command": "PRIVATE"})
    del value["receiver_arrival"]
    with pytest.raises(RecordError, match="record_shape_mismatch"):
        from_mapping(Observation, value)


def test_roundtrip_resume_and_no_duplicate_count(tmp_path) -> None:
    run = spec()
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        first = store.append(run, o)
        assert first == store.append(run, o)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        assert store.read(run) == [o]
        assert store.summary(run)["state"] == "running"
        assert store.summary(run)["observation_count"] == 1
        store.finish(run, "2026-09-06T01:02:00Z")
        store.finish(run, "2026-09-06T01:02:00Z")
        assert store.append(run, o) == first
        assert store.summary(run)["state"] == "complete"
        assert "run_id" not in store.summary(run)
        assert store.summary(run)["native_hook_observed_count"] == 0


def test_revision_conflict_and_cross_run_rejected(tmp_path) -> None:
    run = spec()
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        for changed in [replace(run, detector_revision="other"), replace(run, policy_revision="new")]:
            with pytest.raises(StoreError, match="run_revision_mismatch"):
                store.start(changed)
            with pytest.raises(StoreError, match="run_revision_mismatch"):
                store.append(changed, observed(changed))
        with pytest.raises(StoreError, match="run_identity_mismatch"):
            store.append(run, observed(spec()))


def test_gap_reorder_and_identity_conflict_rejected(tmp_path) -> None:
    run = spec()
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        with pytest.raises(StoreError, match="step_order_mismatch"):
            store.append(run, replace(o, step_no=2))
        store.append(run, o)
        with pytest.raises(StoreError, match="observation_identity_conflict"):
            store.append(run, replace(o, decision="deny"))
        second = replace(o, step_id=uuid.uuid4().hex, tool_use_id=uuid.uuid4().hex, step_no=2)
        store.append(run, second)
        with pytest.raises(StoreError, match="step_order_mismatch"):
            store.append(run, replace(o, step_id=uuid.uuid4().hex, tool_use_id=uuid.uuid4().hex))
        assert len(store.read(run)) == 2


def test_trial_and_step_budget_rejected_without_partial_write(tmp_path) -> None:
    run = spec(max_trials=1, max_steps=1)
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        store.append(run, o)
        with pytest.raises(StoreError, match="trial_budget_exhausted"):
            store.append(run, observed(run))
        with pytest.raises(StoreError, match="step_budget_exhausted"):
            store.append(run, replace(
                o, step_no=2, step_id=uuid.uuid4().hex, tool_use_id=uuid.uuid4().hex,
            ))
        assert len(store.read(run)) == 1
        store.finish(run, "2026-09-06T01:03:00Z", exhausted=True)
        assert store.summary(run)["state"] == "budget_exhausted"


def test_finished_run_rejects_new_observation_and_different_finish(tmp_path) -> None:
    run = spec()
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        with pytest.raises(StoreError, match="finish_before_start"):
            store.finish(run, "2026-09-06T00:00:00Z")
        store.finish(run, "2026-09-06T01:00:00.100Z")
        with pytest.raises(StoreError, match="run_already_finished"):
            store.append(run, observed(run))
        with pytest.raises(StoreError, match="finish_conflict"):
            store.finish(run, "2026-09-06T01:00:00.100Z", exhausted=True)


def test_unrelated_directory_is_untouched(tmp_path) -> None:
    private = tmp_path / "user-data"
    private.mkdir()
    file = private / "runtime.sqlite3"
    file.write_bytes(b"USER_OWNED_DO_NOT_OPEN")
    with pytest.raises(StoreError, match="unrelated_storage_directory"):
        TrialStore(private)
    assert list(private.iterdir()) == [file]
    assert file.read_bytes() == b"USER_OWNED_DO_NOT_OPEN"


def test_symlink_directory_and_database_rejected(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(StoreError, match="unsafe_storage_path"):
        TrialStore(link)
    folder = tmp_path / "trial"
    with TrialStore(folder):
        pass
    (folder / "trials.sqlite3").rename(folder / "old")
    (folder / "trials.sqlite3").symlink_to(folder / "old")
    with pytest.raises(StoreError, match="unsafe_storage_path"):
        TrialStore(folder)


def test_future_schema_is_refused_not_migrated(tmp_path) -> None:
    folder = tmp_path / "trial"
    with TrialStore(folder):
        pass
    with sqlite3.connect(folder / "trials.sqlite3") as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(StoreError, match="storage_schema_mismatch"):
        TrialStore(folder)
    with sqlite3.connect(folder / "trials.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99


def test_stored_malformed_record_is_not_silently_accepted(tmp_path) -> None:
    run = spec()
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        store.append(run, observed(run))
        store._connection.execute("UPDATE lab_observation SET payload='{}'")
        with pytest.raises(StoreError, match="invalid_stored_record"):
            store.read(run)


def test_stored_identity_mismatch_is_detected(tmp_path) -> None:
    run = spec()
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        store.append(run, o)
        payload = json.dumps(asdict(replace(o, run_id=uuid.uuid4().hex)))
        store._connection.execute("UPDATE lab_observation SET payload=?", (payload,))
        with pytest.raises(StoreError, match="invalid_stored_identity"):
            store.read(run)


def test_storage_budget_does_not_delete_records(tmp_path, monkeypatch) -> None:
    run = spec()
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        monkeypatch.setattr("hook_monitor.evaluation.flow_lab.storage.MAX_BYTES", 1)
        with pytest.raises(StoreError, match="storage_budget_exhausted"):
            store.append(run, observed(run))
        assert store.read(run) == []


def reservation(o):
    return {
        "attempt_id": o.attempt_id, "step_id": o.step_id, "tool_use_id": o.tool_use_id,
        "step_no": o.step_no, "reserved_at": o.recorded_at,
    }


def test_reservation_survives_crash_and_never_authorizes_duplicate_send(tmp_path) -> None:
    run = spec()
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        assert store.reserve(run, **reservation(o)) is True
    with TrialStore(tmp_path / "trial") as store:
        assert store.reserve(run, **reservation(o)) is False
        assert len(store.pending(run)) == 1
        with pytest.raises(StoreError, match="unresolved_operations"):
            store.finish(run, "2026-09-06T01:03:00Z")
        assert store.summary(run)["unresolved_count"] == 1
        unknown = replace(
            o, process_started="unknown", network_attempt="unknown", receiver_arrival="unknown",
            protected_arrival="unknown", task_success="unknown", observer_state="partial",
            termination="infrastructure_error",
        )
        store.append(run, unknown)
        assert store.pending(run) == []
        assert store.reserve(run, **reservation(o)) is False
        assert "incomplete_observation" in store.read(run)[0].outcomes()


def test_unresolved_attempt_does_not_advance_or_change_identity(tmp_path) -> None:
    run = spec()
    o = observed(run)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        store.reserve(run, **reservation(o))
        second = replace(o, step_id=uuid.uuid4().hex, tool_use_id=uuid.uuid4().hex, step_no=2)
        with pytest.raises(StoreError, match="attempt_has_unresolved_operation"):
            store.reserve(run, **reservation(second))
        with pytest.raises(StoreError, match="reservation_conflict"):
            store.append(run, replace(o, tool_use_id=uuid.uuid4().hex))
        with pytest.raises(StoreError, match="reservation_conflict"):
            store.reserve(run, **reservation(replace(o, attempt_id=uuid.uuid4().hex)))


def test_pending_reservations_consume_trial_budget(tmp_path) -> None:
    run = spec(max_trials=1)
    with TrialStore(tmp_path / "trial") as store:
        store.start(run)
        store.reserve(run, **reservation(observed(run)))
        with pytest.raises(StoreError, match="trial_budget_exhausted"):
            store.reserve(run, **reservation(observed(run)))
