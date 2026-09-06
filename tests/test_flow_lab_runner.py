from __future__ import annotations

import uuid

import pytest

from hook_monitor.evaluation.flow_lab import runner
from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.storage import TrialStore


class FakeTransport:
    receiver = "synthetic-receiver"

    def __init__(self):
        self.source = "public"
        self.sent = False
        self.down = False
        self.disconnected = False

    def prepare(self, step_id, *, source, encoding):
        self.source = source
        self.sent = False
        return "synthetic-command"

    def guard(self, *a, **kw):
        return "deny"

    def send(self, *a, disconnected=False):
        self.sent = True
        self.disconnected = disconnected
        return not (disconnected or self.down)

    def delivery(self, step_id):
        if self.down:
            return "unknown", "unknown"
        arrived = self.sent and not self.disconnected
        return ("yes" if arrived else "no", "yes" if arrived and self.source != "public" else "no")


def spec():
    return RunSpec(
        run_id=uuid.uuid4().hex, suite_version="test", detector_revision="test",
        policy_revision="test", environment_digest="a" * 64, started_at=utc_now(),
    )


def test_all_fixed_scenarios_and_groups(monkeypatch, tmp_path):
    transport = FakeTransport()
    monkeypatch.setattr(runner, "command", lambda *a, **kw: setattr(transport, "down", True))
    run = spec()
    with TrialStore(tmp_path / "lab") as store:
        store.start(run)
        observations = [runner.run_scenario(transport, store, run, s) for s in runner.SCENARIOS]
        assert all(runner.validate_controls(observations).values())
        groups = runner.grouped_results(observations)
        assert groups["detector_enforcement"]["observation_count"] == 4
        assert groups["detector_enforcement"]["outcomes"]["unnecessary_stop"] == 1
        assert "protected_delivery" not in groups["detector_enforcement"]["outcomes"]
        assert groups["receiver_controls"]["observation_count"] == 4
        assert groups["injected_faults"]["observation_count"] == 3
        assert groups["injected_faults"]["outcomes"]["denial_delivery_conflict"] == 1
        assert store.summary(run)["native_hook_observed_count"] == 0
        assert store.pending(run) == []


def test_guard_failure_leaves_reservation_and_no_operation(monkeypatch, tmp_path):
    transport = FakeTransport()
    def fail(*a, **kw):
        raise LabError("guard_receipt_missing")
    monkeypatch.setattr(transport, "guard", fail)
    run = spec()
    with TrialStore(tmp_path / "lab") as store:
        store.start(run)
        with pytest.raises(LabError, match="guard_receipt_missing"):
            runner.run_scenario(transport, store, run, runner.SCENARIOS[0])
        assert len(store.pending(run)) == 1
        assert store.read(run) == []
        assert not transport.sent


def test_false_reservation_never_dispatches(monkeypatch, tmp_path):
    transport = FakeTransport()
    run = spec()
    with TrialStore(tmp_path / "lab") as store:
        store.start(run)
        monkeypatch.setattr(store, "reserve", lambda *a, **kw: False)
        with pytest.raises(LabError, match="already_reserved"):
            runner.run_scenario(transport, store, run, runner.SCENARIOS[0])
        assert not transport.sent


def test_cli_failure_does_not_print_underlying_os_message(monkeypatch, capsys):
    def fail(*a, **kw):
        raise OSError("PRIVATE_PATH")
    monkeypatch.setattr(runner, "run_suite", fail)
    assert runner.main(["--repository", ".", "--output-directory", "unused"]) == 1
    result = capsys.readouterr().out
    assert "trial_io_error" in result
    assert "PRIVATE_PATH" not in result
