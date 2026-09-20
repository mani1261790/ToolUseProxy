from dataclasses import replace
import json

import pytest

from hook_monitor.evaluation.flow_forecast.branches import Transfer
from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import checked_task_world as module, task_world_collection, task_world_interventions, task_catalog
from research.flow_forecast.task_worlds import operation_script
from test_flow_forecast_task_world_collection import Transport
from test_flow_forecast_task_world_collection import lab as world_lab  # noqa: F401
from test_flow_forecast_task_world_interventions import lab as intervention_lab  # noqa: F401


@pytest.fixture
def captures(request, monkeypatch, tmp_path):
    request.getfixturevalue('world_lab')
    request.getfixturevalue('intervention_lab')
    monkeypatch.setattr(task_world_collection, 'build_context', lambda _: b'fixture')
    def prepare(self, number, step):
        self.numbers[step] = number
        return operation_script(self.name, number, self.variant, '172.18.0.2', step)
    monkeypatch.setattr(Transport, 'prepare_step', prepare)
    task_world_interventions.run(tmp_path, 'ledger', tmp_path / 'interventions')
    return tmp_path


@pytest.mark.parametrize('variant,expected', [('public', 'no'), ('include_private', 'yes')])
def test_closed_computation_and_projection_supply_coarse_truth(captures, variant, expected):
    capture = captures / 'capture'
    task_world_collection.run(captures, 'ledger', variant, capture)
    data, audit = module.read_checked_capture(capture, captures / 'interventions')
    assert audit['closed_computation_evidence']['general_semantic_truth'] is False
    for branch in data.branches:
        label = label_future(branch, 4)
        assert label.protected_arrival == expected
        assert label.unknown_edges == 0
    assert any(e.relation == 'closed_compute' for b in data.branches for e in b.transfers)
    pairs = captures / 'pairs.json'
    pairs.write_text(json.dumps([{'capture': str(capture), 'interventions': str(captures / 'interventions')}]))
    collection = captures / 'collection'
    task_catalog.main(['--checked-task-worlds', str(pairs), '--output', str(collection)])
    assert task_catalog.read_collection(collection)[0] == data


def test_reread_cannot_attach_proof_to_changed_capture(captures, monkeypatch):
    capture = captures / 'capture'
    task_world_collection.run(captures, 'ledger', 'public', capture)
    original = module.bind_capture
    def changed(*args):
        result = original(*args)
        result['capture_report_sha'] = 'c' * 64
        return result
    monkeypatch.setattr(module, 'bind_capture', changed)
    with pytest.raises(ForecastDataError, match='checked_capture_changed'):
        module.read_checked_capture(capture, captures / 'interventions')


@pytest.mark.parametrize('relation,evidence', [
    ('closed_compute', 'checked_bytes'), ('json_projection', 'checked_bytes'),
    ('semantic', 'checked_computation'), ('copy', 'checked_json_projection'),
])
def test_contract_relations_require_their_specific_evidence(relation, evidence):
    with pytest.raises(ForecastDataError):
        Transfer('a', 'b', 1, relation, evidence, 'a' * 64)


def test_generic_semantic_edge_remains_unknown():
    edge = Transfer('a', 'b', 1, 'semantic', 'unknown', None)
    with pytest.raises(ForecastDataError):
        replace(edge, evidence='checked_bytes', evidence_digest='a' * 64)


def test_blocked_future_stays_censored_after_contract(captures, monkeypatch):
    original = Transport.guard_step
    def deny(self, cmd, session, step):
        original(self, cmd, session, step)
        self.guard_receipts[step]['decision'] = 'deny'
        return 'deny'
    monkeypatch.setattr(Transport, 'guard_step', deny)
    capture = captures / 'capture'
    task_world_collection.run(captures, 'ledger', 'include_private', capture)
    data, _ = module.read_checked_capture(capture, captures / 'interventions')
    assert len(data.branches) == 2
    labels = {b.policy_mode: label_future(b, 4) for b in data.branches}
    assert labels['observe'].protected_arrival == 'yes'
    assert labels['enforce'].protected_arrival == 'unknown' and labels['enforce'].censored
