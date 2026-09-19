import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_lab.agent import Action
from hook_monitor.evaluation.flow_lab.controller import execute_action
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import paired_collection as module
from test_flow_lab_controller import context as context
from test_flow_lab_task_completion import finish


class Transport:
    instances = []

    def __init__(self, image):
        self.prepared, self.delivered = {}, set()
        self.closed = False
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def prepare(self, step, **action):
        self.prepared[step] = action
        return step

    def guard(self, command, **_):
        return 'allow' if self.prepared[command]['source'] == 'public' else 'deny'

    def send(self, command, **kwargs):
        self.delivered.add(command)
        return True

    def delivery(self, step):
        if step not in self.delivered:
            return 'no', 'no'
        return 'yes', 'no' if self.prepared[step]['source'] == 'public' else 'yes'


@pytest.fixture
def lab(context, monkeypatch):
    finish(context)
    Transport.instances = []
    monkeypatch.setattr(module, 'AdaptiveTransport', Transport)
    monkeypatch.setattr(module, 'build_context', lambda _: b'source-only-fixture')
    monkeypatch.setattr(module, 'build_image', lambda *args, **kwargs: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(module, 'check_isolation', lambda _: None)
    return context[0].directory


def test_fixed_plan_runs_both_modes_in_fresh_receivers_with_no_new_model_calls(lab, tmp_path):
    output = tmp_path / 'paired'
    result = module.run(tmp_path, lab, output)
    assert result['trial_count'] == 8 and result['additional_model_calls'] == 0
    assert result['independent_new_task_count'] == 0 and result['unused_holdout'] is False
    assert [row['mode'] for row in result['conditions']] == ['observe', 'enforce']
    assert all(row['task_completion']['status'] == 'achieved' for row in result['conditions'])
    assert len(Transport.instances) == 2 and all(item.closed for item in Transport.instances)
    assert result['conditions'][0]['source_steps'] == result['conditions'][1]['source_steps']
    assert result == json.loads((output / 'report.json').read_text())
    intent = json.loads((output / 'intent.json').read_text())
    assert intent['planned_trials'] == 8 and intent['planned_operations'] == result['operation_count'] == 8
    data = module.read_dataset(output / 'dataset')
    assert len(data.branches) == 2
    assert {row.policy_mode for row in data.branches} == {'observe', 'enforce'}
    assert len({row.prefix.snapshot_digest for row in data.branches}) == 1
    assert all(row.probability is None and row.sampling == 'adaptive_search' for row in data.branches)
    with pytest.raises(FileExistsError):
        module.run(tmp_path, lab, output)
    assert len(Transport.instances) == 2


def test_completion_intent_exists_before_first_dispatch(lab, tmp_path, monkeypatch):
    output = tmp_path / 'paired'
    original = Transport.send
    def inspected(self, command, **kwargs):
        assert (output / 'intent.json').is_file()
        assert (output / 'source-evidence.json').is_file()
        return original(self, command)
    monkeypatch.setattr(Transport, 'send', inspected)
    module.run(tmp_path, lab, output)


def test_interruption_retains_intent_without_completion_or_silent_retry(lab, tmp_path, monkeypatch):
    output = tmp_path / 'paired'
    def fail(*_, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(Transport, 'send', fail)
    with pytest.raises(KeyboardInterrupt):
        module.run(tmp_path, lab, output)
    assert (output / 'intent.json').is_file() and not (output / 'report.json').exists()
    assert all(item.closed for item in Transport.instances)
    with pytest.raises(FileExistsError):
        module.run(tmp_path, lab, output)


def test_invalid_budgets_and_attempts_precede_output_creation(lab, tmp_path):
    output = tmp_path / 'paired'
    for kwargs in ({'seconds': 1801}, {'seconds': True}, {'attempt': 0}, {'attempt': 2}):
        with pytest.raises(ForecastDataError):
            module.run(tmp_path, lab, output, **kwargs)
    assert not output.exists()


def test_action_count_cannot_exceed_twenty_including_controls(lab, tmp_path, monkeypatch):
    _, audit = module.import_search(lab)
    audit['records'] *= 8
    monkeypatch.setattr(module, 'import_search', lambda _: (None, audit))
    with pytest.raises(ForecastDataError, match='pair_trial_budget_exhausted'):
        module.run(tmp_path, lab, tmp_path / 'paired')
    assert not (tmp_path / 'paired').exists()


def test_observe_executes_denied_synthetic_action_but_enforce_does_not(context):
    import uuid
    _, store, spec, _, _ = context
    store.start(spec)
    with Transport('fixture') as transport:
        rows = [execute_action(transport, store, spec, Action('protected', 'plain'),
                               uuid.uuid4().hex, uuid.uuid4().hex, 1, policy_mode=mode)
                for mode in ('observe', 'enforce')]
    assert rows[0].decision == rows[1].decision == 'deny'
    assert rows[0].policy_mode == 'observe' and rows[0].protected_arrival == 'yes'
    assert rows[1].policy_mode == 'enforce' and rows[1].process_started == 'no'
    assert rows[1].protected_arrival == 'no'
    with pytest.raises(LabError, match='invalid_trial_policy_mode'):
        execute_action(transport, store, spec, Action('protected', 'plain'),
                       uuid.uuid4().hex, uuid.uuid4().hex, 1, policy_mode='other')


def test_time_and_storage_exhaustion_prevent_first_dispatch(lab, tmp_path, monkeypatch):
    ticks = iter((0, 601))
    with monkeypatch.context() as patch:
        with pytest.raises(ForecastDataError, match='pair_time_budget_exhausted'):
            module.run(tmp_path, lab, tmp_path / 'time', clock=lambda: next(ticks))
    with monkeypatch.context() as patch:
        patch.setattr(module, 'MAX_STORAGE', 1)
        with pytest.raises(ForecastDataError, match='pair_storage_budget_exhausted'):
            module.run(tmp_path, lab, tmp_path / 'storage')
    assert not Transport.instances


def test_failed_controls_do_not_dispatch_task(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(Transport, 'delivery', lambda *_: ('unknown', 'unknown'))
    output = tmp_path / 'pair'
    with pytest.raises(ForecastDataError, match='pair_controls_failed'):
        module.run(tmp_path, lab, output)
    assert len(Transport.instances) == 1
    assert len(Transport.instances[0].prepared) == 3
    assert not (output / 'report.json').exists()


def test_multiple_actions_count_operations_separately_from_trial_plans(lab, tmp_path, monkeypatch):
    audit, records, proposal = module.selected_plan(lab, 1)
    from hook_monitor.evaluation.flow_lab.agent import Proposal
    proposal = Proposal('propose', proposal.actions * 2)
    second = {**records[0], 'step_id': '0' * 32}
    monkeypatch.setattr(module, 'selected_plan', lambda *_: (audit, [records[0], second], proposal))
    result = module.run(tmp_path, lab, tmp_path / 'pair')
    assert result['operation_count'] == 10
    assert result['trial_count'] == 8


def test_cli_returns_closed_failure_without_dispatch(lab, tmp_path, capsys):
    assert module.main(['--repository', str(tmp_path), '--search-directory', str(lab),
                        '--output', str(tmp_path / 'pair'), '--seconds', '0']) == 1
    assert json.loads(capsys.readouterr().out) == {
        'status': 'not_completed', 'reason': 'invalid_pair_time_budget'}
    assert not Transport.instances and not (tmp_path / 'pair').exists()
