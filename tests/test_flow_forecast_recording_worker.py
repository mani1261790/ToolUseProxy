from dataclasses import replace
import sqlite3
import subprocess

from research.flow_forecast.artifacts import save_model
from research.flow_forecast.model import fit
from research.flow_forecast.recording.contracts import Current
from research.flow_forecast.recording.worker import isolated_prediction, run_one
from test_flow_forecast_baselines import dataset
from test_flow_forecast_recording import request
from test_flow_forecast_recording_journal import configured


def ready(tmp_path):
    journal = configured(tmp_path)
    model = fit(dataset())
    path = tmp_path / 'model.json'
    save_model(model, path)
    item = replace(request(), model_digest=model.model_digest, policy_mode='observe')
    journal.enqueue(item, current=item.binding, now=1001)
    return journal, item, path


def test_actual_disposable_process_records_a_bound_forecast(tmp_path):
    journal, item, path = ready(tmp_path)
    result = run_one(journal, 'workspace', path, read_current=lambda _: Current(item.binding, item.model_digest), clock=lambda: 1001)
    assert result['status'] == 'recorded'
    stored = journal.history('workspace')[0]['result']
    assert stored['record_only'] is True
    assert stored['forecast']['protected_probability'] == 1
    assert stored['binding']['candidate_id'] == item.binding.candidate_id
    assert 'action' not in stored and 'allow' not in stored


def test_state_changed_during_prediction_is_discarded(tmp_path):
    journal, item, path = ready(tmp_path)
    calls = []
    def current(_):
        calls.append(True)
        return Current(item.binding if len(calls) == 1 else replace(item.binding, policy_digest='f' * 64), item.model_digest)
    result = run_one(journal, 'workspace', path, read_current=current, clock=lambda: 1001)
    assert result['status'] == 'input_version_changed'
    assert journal.history('workspace')[0]['result'] is None


def test_unconfigured_project_never_reads_model_or_input(tmp_path):
    journal, _, path = ready(tmp_path)
    def forbidden(*args):
        raise AssertionError('unconfigured project must not be touched')
    result = run_one(journal, 'other-workspace', path, read_current=forbidden, predictor=forbidden)
    assert result == {'status': 'idle'}


def test_missing_model_and_input_database_fault_are_diagnostics(tmp_path):
    journal, item, path = ready(tmp_path)
    result = run_one(journal, 'workspace', path.with_name('missing.json'), read_current=lambda _: Current(item.binding, item.model_digest),
                     clock=lambda: 1001)
    assert result['status'] == 'model_missing'
    newer = replace(item, created_at=1002)
    journal.enqueue(newer, current=newer.binding, now=1002)
    def unavailable(_):
        raise sqlite3.OperationalError('synthetic database unavailable')
    result = run_one(journal, 'workspace', path, read_current=unavailable, clock=lambda: 1002)
    assert result['status'] == 'input_database_failure'


def test_timeout_and_disable_do_not_publish_a_forecast(tmp_path, monkeypatch):
    journal, item, path = ready(tmp_path)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('synthetic', 3)
    monkeypatch.setattr(subprocess, 'run', timeout)
    result = run_one(journal, 'workspace', path, read_current=lambda _: Current(item.binding, item.model_digest), clock=lambda: 1001)
    assert result['status'] == 'timeout'
    monkeypatch.undo()
    newer = replace(item, created_at=1002)
    journal.enqueue(newer, current=newer.binding, now=1002)
    def disabled(request, model_path):
        value = isolated_prediction(request, model_path)
        journal.configure('workspace', enabled=False)
        return value
    result = run_one(journal, 'workspace', path, read_current=lambda _: Current(newer.binding, newer.model_digest), predictor=disabled,
                     clock=lambda: 1002)
    assert result['status'] == 'discarded'


def test_live_structure_is_out_of_domain_until_research_conditions_are_met(tmp_path):
    journal, item, path = ready(tmp_path)
    journal.configure('workspace', enabled=False)
    generation = journal.configure('workspace', enabled=True)
    live = replace(item, binding=replace(item.binding, project_generation=generation), input_scope='recorded_structure')
    journal.enqueue(live, current=live.binding, now=1001)
    def forbidden(*args):
        raise AssertionError('out-of-domain input must not run inference')
    result = run_one(journal, 'workspace', path, read_current=lambda _: Current(live.binding, live.model_digest), predictor=forbidden,
                     clock=lambda: 1001)
    assert result['status'] == 'out_of_domain'


def test_model_selection_changed_during_prediction_discards_the_old_model_result(tmp_path):
    journal, item, path = ready(tmp_path)
    calls = []
    def current(_):
        calls.append(True)
        return Current(item.binding, item.model_digest if len(calls) == 1 else 'e' * 64)
    result = run_one(journal, 'workspace', path, read_current=current, clock=lambda: 1001)
    assert result['status'] == 'model_version_changed'
    assert journal.history('workspace')[0]['result'] is None


def test_real_child_timeout_is_bounded_and_does_not_return_a_forecast(tmp_path):
    _, item, path = ready(tmp_path)
    result = isolated_prediction(item, path, timeout=.001)
    assert result == {'status': 'timeout'}
