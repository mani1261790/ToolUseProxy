from dataclasses import replace
import uuid

import pytest

from hook_monitor.evaluation.flow_lab import search_runner as module
from hook_monitor.evaluation.flow_lab import runner
from hook_monitor.evaluation.flow_lab.budget import Budget
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.storage import TrialStore


@pytest.fixture
def lab(monkeypatch, tmp_path):
    instances = {}
    model_calls = []
    proposals = [{"status": "complete", "actions": []}]
    class Transport:
        def __init__(self, image):
            self.receiver = uuid.uuid4().hex
            self.down = False
            self.sent = False
            self.disconnected = False
            self.source = "public"
            instances[self.receiver] = self
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def prepare(self, step, **values):
            self.source = values["source"]
            self.sent = False
            return "synthetic-only"
        def guard(self, *args, **kwargs):
            return "deny"
        def send(self, command, disconnected=False):
            self.sent = True
            self.disconnected = disconnected
            return not (self.down or disconnected)
        def delivery(self, step):
            if self.down:
                return "unknown", "unknown"
            arrived = self.sent and not self.disconnected
            return ("yes" if arrived else "no", "yes" if arrived and self.source != "public" else "no")
    class Provider:
        def __init__(self, model):
            self.model_id = model
        def propose(self, feedback, **kwargs):
            model_calls.append(feedback)
            value = proposals.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
    monkeypatch.setattr(module, "CodexProvider", Provider)
    monkeypatch.setattr(module, "FixedTransport", Transport)
    monkeypatch.setattr(module, "AdaptiveTransport", Transport)
    monkeypatch.setattr(module, "build_context", lambda _: b"synthetic-context")
    monkeypatch.setattr(module, "build_image", lambda *a, **kw: "sha256:" + "a" * 64)
    monkeypatch.setattr(module, "check_isolation", lambda _: None)
    monkeypatch.setattr(runner, "command", lambda args: setattr(instances[args[-1]], "down", True))
    return tmp_path / "search", model_calls, proposals, instances


def test_baseline_and_current_receiver_are_separate_and_counted(lab, tmp_path):
    folder, calls, proposals, instances = lab
    result = module.execute(tmp_path, folder, "synthetic-model")
    assert result["status"] == "completed"
    assert len(calls) == 1
    assert len(instances) == 2
    assert all(result["controls"].values())
    with TrialStore(folder / "controls") as controls:
        assert controls.trial_count() == 13
    assert module.execute(tmp_path, folder, "synthetic-model")["status"] == "completed"
    assert len(instances) == 2
    assert len(calls) == 1


def test_failure_in_baseline_is_not_skipped_on_retry(lab, tmp_path, monkeypatch):
    folder, calls, _, _ = lab
    monkeypatch.setattr(module, "validate_controls", lambda _: {"failed": False})
    for _ in range(2):
        with pytest.raises(LabError, match="trial_control_failed"):
            module.execute(tmp_path, folder, "synthetic-model")
    assert calls == []
    with TrialStore(folder / "controls") as controls:
        assert controls.trial_count() == 11


def test_resume_revalidates_receiver_and_charges_new_controls(lab, tmp_path):
    folder, calls, proposals, instances = lab
    proposals[:] = [LabError("model_auth_required")]
    assert module.execute(tmp_path, folder, "synthetic-model")["status"] == "model_auth_required"
    proposals[:] = [{"status": "complete", "actions": []}]
    assert module.execute(tmp_path, folder, "synthetic-model")["status"] == "completed"
    assert len(instances) == 3
    with TrialStore(folder / "controls") as controls:
        assert controls.trial_count() == 15


def test_completed_run_cannot_be_relabelled_with_other_model(lab, tmp_path):
    folder, _, _, _ = lab
    module.execute(tmp_path, folder, "synthetic-model")
    with pytest.raises(LabError, match="search_revision_mismatch"):
        module.execute(tmp_path, folder, "other-model")


def test_controls_must_fit_total_budget_before_dispatch(lab, tmp_path):
    folder, calls, _, instances = lab
    result = module.execute(tmp_path, folder, "synthetic-model", budget=replace(Budget(), trials=12))
    assert result["status"] == "trial_budget_exhausted"
    assert not calls and not instances


def test_storage_budget_prevents_control_dispatch(lab, tmp_path):
    folder, calls, _, instances = lab
    result = module.execute(tmp_path, folder, "synthetic-model", budget=replace(Budget(), storage_bytes=1))
    assert result["status"] == "storage_budget_exhausted"
    assert not calls and not instances


def test_completed_run_can_be_read_without_model_executable(lab, tmp_path, monkeypatch):
    folder, _, _, _ = lab
    module.execute(tmp_path, folder, "synthetic-model")
    def missing(*args):
        pytest.fail("completed run must not require a model process")
    monkeypatch.setattr(module, "CodexProvider", missing)
    assert module.execute(tmp_path, folder, "synthetic-model")["status"] == "completed"


def test_unfinished_run_refuses_changed_search_implementation(lab, tmp_path, monkeypatch):
    folder, calls, proposals, _ = lab
    proposals[:] = [LabError("model_auth_required")]
    module.execute(tmp_path, folder, "synthetic-model")
    monkeypatch.setattr(module, "implementation_revision", lambda: "b" * 64)
    with pytest.raises(LabError, match="search_revision_mismatch"):
        module.execute(tmp_path, folder, "synthetic-model")
    assert len(calls) == 1
