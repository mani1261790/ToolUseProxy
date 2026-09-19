import json

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY
from research.flow_forecast import task_world_collection as module
from research.flow_forecast.task_worlds import definition, encoded, observe_bytes
from test_flow_forecast_stateful_collection import Transport as Base


class Transport(Base):
    def __init__(self, image, name, variant, mode):
        super().__init__(image, {'source': 'public', 'operations': ['read', 'copy', 'save', 'send']}, mode)
        self.name, self.variant = name, variant

    def execute_step(self, cmd, step):
        number = self.numbers[step]
        world = definition(self.name)
        body = world['input'] if number == 1 else world['answer']
        if number >= 3 and self.variant == 'include_private':
            body['private'] = CANARY
        row = observe_bytes(self.name, number, self.variant, encoded(body), CANARY)
        if number == 4:
            row['receiver'] = {'protected': self.variant == 'include_private', 'body_sha': row['body_sha']}
        return row


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(module, 'WorldTransport', Transport)
    monkeypatch.setattr(module, 'build_context', lambda _: b'world-fixture')
    monkeypatch.setattr(module, 'build_image', lambda *a, **k: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(module, 'check_isolation', lambda _: None)


@pytest.mark.parametrize('name', ['inventory', 'calendar', 'ledger'])
@pytest.mark.parametrize('variant', ['public', 'include_private'])
def test_closed_batch_records_tasks_and_separates_leak_from_completion(lab, tmp_path, name, variant):
    out = tmp_path / 'capture'
    report = module.run(tmp_path, name, variant, out)
    assert report['trial_charges'] == 14
    assert report['new_model_calls'] == 0 and report['independent_new_tasks_accepted'] == 0
    assert report['f01_import'] == 'not_supported_semantic_truth_unknown'
    for row in report['conditions']:
        assert row['task_achieved'] == (variant == 'public')
        assert row['protected_received'] == (variant == 'include_private')
    assert json.loads((out / 'report.json').read_text()) == report
    with pytest.raises(FileExistsError):
        module.run(tmp_path, name, variant, out)


def test_invalid_parameters_do_not_create_batch(tmp_path):
    output = tmp_path / 'capture'
    for world, variant, seconds in [('other', 'public', 180), ('inventory', 'free-code', 180),
                                    ('inventory', 'public', 1801), ('inventory', 'public', True)]:
        with pytest.raises(LabError):
            module.run(tmp_path, world, variant, output, seconds=seconds)
        assert not output.exists()


def test_expired_batch_keeps_intent_without_dispatch_or_report(lab, tmp_path):
    moments = iter([0, 181])
    out = tmp_path / 'capture'
    with pytest.raises(LabError, match='budget_exhausted'):
        module.run(tmp_path, 'inventory', 'public', out, clock=lambda: next(moments))
    assert (out / 'intent.json').exists()
    assert not (out / 'execution.json').exists()
    assert not (out / 'report.json').exists()
