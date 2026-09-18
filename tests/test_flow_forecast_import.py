import hashlib
import sqlite3
import uuid

import pytest

from hook_monitor.evaluation.flow_lab.budget import Budget
from hook_monitor.evaluation.flow_lab.controller import run_search
from hook_monitor.evaluation.flow_lab.models import RunSpec, utc_now
from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
from hook_monitor.evaluation.flow_lab.storage import TrialStore
from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_forecast.search_import import import_search


class Provider:
    model_id = 'synthetic-test'
    def __init__(self):
        self.values = iter([{'status': 'propose', 'actions': [{'source': 'protected', 'encoding': 'plain'}]},
                            {'status': 'complete', 'actions': []}])
    def propose(self, *args, **kwargs):
        return next(self.values)


class Transport:
    def __init__(self, arrived=False):
        self.arrived = arrived
    def prepare(self, *args, **kwargs):
        return 'synthetic-command'
    def guard(self, *args, **kwargs):
        return 'allow' if self.arrived else 'deny'
    def send(self, *args):
        return True
    def delivery(self, *args):
        return ('yes', 'yes') if self.arrived else ('no', 'no')


def create_search(path, arrived=False):
    spec = RunSpec(uuid.uuid4().hex, 'adaptive-v1', 'source-test', 'policy-test',
                   'a' * 64, utc_now(), mode='adaptive_search')
    with SearchJournal(path) as journal, TrialStore(path / 'trials') as store:
        result = run_search(journal, store, spec, Transport(arrived), Provider(), Budget())
        assert result['status'] == 'completed'
    return spec


def test_historical_import_is_read_only_and_stopped_samples_stay_unknown(tmp_path):
    path = tmp_path / 'search'
    create_search(path)
    files = tuple(path.rglob('*.sqlite3'))
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    data, audit = import_search(path)
    assert len(data.branches) == 1
    assert data.branches[0].probability is None
    assert data.branches[0].termination == 'blocked'
    assert label_future(data.branches[0], 4).protected_arrival == 'unknown'
    assert data.summary()['unpaired_adaptive_count'] == 1
    assert 'no_paired_counterfactual' in audit['limitations']
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in files} == before


def test_arrived_search_does_not_invent_intermediate_path_truth(tmp_path):
    path = tmp_path / 'search'
    create_search(path, arrived=True)
    data, audit = import_search(path)
    branch = data.branches[0]
    assert branch.receiver_arrivals
    assert branch.transfers[0].evidence == 'unknown'
    assert label_future(branch, 4).routes == ()
    assert label_future(branch, 4).protected_arrival == 'unknown'
    assert audit['records'][0]['observation']['protected_arrival'] == 'yes'
    assert branch.prefix.model_input()['observations'] == []


def test_import_rejects_identity_change_and_unrelated_database(tmp_path):
    path = tmp_path / 'search'
    create_search(path)
    with sqlite3.connect(path / 'trials/trials.sqlite3') as conn:
        conn.execute("UPDATE lab_observation SET attempt_id=?", ('e' * 32,))
    with pytest.raises(ForecastDataError):
        import_search(path)
    with sqlite3.connect(path / 'search.sqlite3') as conn:
        conn.execute('PRAGMA application_id=1')
    with pytest.raises(ForecastDataError):
        import_search(path)


def test_unfinished_search_is_not_admitted_to_completed_dataset(tmp_path):
    path = tmp_path / 'search'
    create_search(path)
    with sqlite3.connect(path / 'trials/trials.sqlite3') as conn:
        conn.execute("UPDATE lab_run SET state='running'")
    with pytest.raises(ForecastDataError, match='search_trial_revision_mismatch'):
        import_search(path)
