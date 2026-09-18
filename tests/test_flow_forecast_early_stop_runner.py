from research.flow_forecast.artifacts import save_model
from research.flow_forecast.early_stop_runner import ForecastGate, observed_prefix
from research.flow_forecast.model import fit
from research.flow_forecast.recording.journal import Journal
from test_flow_forecast_baselines import dataset


def test_real_child_gate_and_disable_at_boundary(tmp_path):
    model = tmp_path / 'model.json'
    save_model(fit(dataset()), model)
    journal = Journal.create(tmp_path / 'forecast.db')
    journal.configure('synthetic.test', enabled=True)
    transport = type('Prepared', (), {'prepared': {'step': 'synthetic-command'}})()
    prefix = observed_prefix('public', 'plain', 'fixture-environment')
    gate = ForecastGate(journal, 'synthetic.test', model, transport, prefix, 0)
    assessment = gate(step_id='step', command='synthetic-command', existing_block=False)
    assert assessment.additional_stop
    assert gate.diagnostics[0]['worker_status'] == 'recorded'
    journal.configure('synthetic.test', enabled=False)
    assessment = gate(step_id='step', command='synthetic-command', existing_block=False)
    assert not assessment.stop and assessment.reason == 'experiment_disabled'
    assert gate(step_id='step', command='synthetic-command', existing_block=True).stop


def test_prepared_command_change_is_not_the_same_operation(tmp_path):
    model = tmp_path / 'model.json'
    save_model(fit(dataset()), model)
    journal = Journal.create(tmp_path / 'forecast.db')
    journal.configure('synthetic.test', enabled=True)
    transport = type('Prepared', (), {'prepared': {'step': 'changed-command'}})()
    gate = ForecastGate(journal, 'synthetic.test', model, transport,
                        observed_prefix('public', 'plain', 'fixture-environment'), 0)
    result = gate(step_id='step', command='original-command', existing_block=False)
    assert not result.stop and result.reason == 'input_version_changed'
    assert journal.history('synthetic.test') == ()


def test_emergency_disable_during_prediction_removes_only_additional_stop(tmp_path, monkeypatch):
    from research.flow_forecast.recording.worker import run_one, isolated_prediction
    model = tmp_path / 'model.json'
    save_model(fit(dataset()), model)
    journal = Journal.create(tmp_path / 'forecast.db')
    journal.configure('synthetic.test', enabled=True)
    transport = type('Prepared', (), {'prepared': {'step': 'synthetic-command'}})()
    gate = ForecastGate(journal, 'synthetic.test', model, transport,
                        observed_prefix('public', 'plain', 'fixture-environment'), 0)
    def disabled(request, path):
        result = isolated_prediction(request, path)
        journal.configure('synthetic.test', enabled=False)
        return result
    def concurrent(*args, **kwargs):
        return run_one(*args, **kwargs, predictor=disabled)
    monkeypatch.setattr('research.flow_forecast.early_stop_runner.run_one', concurrent)
    assessment = gate(step_id='step', command='synthetic-command', existing_block=False)
    assert not assessment.stop and assessment.reason == 'experiment_disabled'
    assert gate.diagnostics[0]['worker_status'] == 'discarded'
    assert gate(step_id='step', command='synthetic-command', existing_block=True).stop


def test_batch_model_is_pinned_before_any_prediction(tmp_path):
    model = tmp_path / 'model.json'
    save_model(fit(dataset()), model)
    journal = Journal.create(tmp_path / 'forecast.db')
    journal.configure('synthetic.test', enabled=True)
    transport = type('Prepared', (), {'prepared': {'step': 'synthetic-command'}})()
    gate = ForecastGate(journal, 'synthetic.test', model, transport,
                        observed_prefix('public', 'plain', 'fixture-environment'), 0,
                        expected_model_digest='f' * 64)
    result = gate(step_id='step', command='synthetic-command', existing_block=False)
    assert not result.stop and result.reason == 'model_version_changed'
    assert journal.history('synthetic.test') == ()
