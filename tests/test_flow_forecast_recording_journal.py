from dataclasses import replace
import sqlite3

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.recording.journal import Journal
from test_flow_forecast_recording import request


def configured(tmp_path):
    journal = Journal.create(tmp_path / 'forecast.sqlite3')
    assert journal.configure('workspace', enabled=True) == 1
    return journal


def test_unconfigured_workspace_does_not_create_or_write_any_record(tmp_path):
    item = request()
    missing = Journal(tmp_path / 'absent.sqlite3')
    assert missing.enqueue(item, current=item.binding, now=1001) == 'unconfigured'
    assert not missing.path.exists()
    journal = Journal.create(tmp_path / 'journal.sqlite3')
    before = journal.path.read_bytes()
    assert journal.enqueue(item, current=item.binding, now=1001) == 'unconfigured'
    assert journal.claim('workspace', now=1001) is None
    assert journal.history('workspace') == ()
    assert journal.path.read_bytes() == before


def test_claim_is_exclusive_and_duplicate_enqueue_does_not_repeat_work(tmp_path):
    journal = configured(tmp_path)
    item = request()
    assert journal.enqueue(item, current=item.binding, now=1001) == 'pending'
    claim, token = journal.claim('workspace', now=1001)
    assert claim == item
    second = Journal(journal.path)
    assert second.claim('workspace', now=1001) is None
    assert second.enqueue(item, current=item.binding, now=1001) == 'running'
    assert second.finish(item, 'wrong-token', status='worker_failed', now=1002) == 'discarded'
    assert journal.finish(item, token, status='recorded', result={'synthetic_result': True}, now=1002) == 'recorded'
    assert second.enqueue(item, current=item.binding, now=1002) == 'recorded'
    assert len(journal.history('workspace')) == 1
    assert journal.history('workspace')[0]['historical_only']


def test_disable_invalidates_in_flight_work_and_reenable_keeps_history(tmp_path):
    journal = configured(tmp_path)
    item = request()
    journal.enqueue(item, current=item.binding, now=1001)
    _, token = journal.claim('workspace', now=1001)
    assert journal.configure('workspace', enabled=False) == 2
    assert journal.finish(item, token, status='recorded', result={}, now=1002) == 'discarded'
    assert journal.history('workspace') == ()
    assert journal.configure('workspace', enabled=True) == 3
    assert journal.history('workspace')[0]['status'] == 'disabled'
    assert journal.enqueue(item, current=item.binding, now=1002) == 'project_generation_changed'
    fresh = replace(item, binding=replace(item.binding, project_generation=3), created_at=1002)
    assert journal.enqueue(fresh, current=fresh.binding, now=1002) == 'pending'
    assert journal.configure('workspace', enabled=True) == 3  # idempotent


def test_recovery_waits_for_lease_deadline_and_discards_late_worker_result(tmp_path):
    journal = configured(tmp_path)
    item = request()
    journal.enqueue(item, current=item.binding, now=1001)
    _, token = journal.claim('workspace', now=1001, lease_seconds=2)
    assert journal.recover('workspace', now=1002.99) == 0
    assert journal.recover('workspace', now=1003) == 1
    assert journal.finish(item, token, status='recorded', result={}, now=1003) == 'discarded'
    assert journal.history('workspace')[0]['status'] == 'interrupted'


def test_expiry_and_worker_deadline_cannot_be_published_as_success(tmp_path):
    journal = configured(tmp_path)
    item = request()
    journal.enqueue(item, current=item.binding, now=1001)
    _, token = journal.claim('workspace', now=1001, lease_seconds=1)
    assert journal.finish(item, token, status='recorded', result={}, now=1002) == 'timeout'
    later = replace(item, created_at=1002)
    journal.enqueue(later, current=later.binding, now=1002)
    assert journal.claim('workspace', now=1032) is None
    assert journal.history('workspace')[0]['status'] == 'expired'


def test_other_database_is_rejected_without_migration_or_mutation(tmp_path):
    path = tmp_path / 'events.db'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE events(event_id TEXT)')
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        Journal.create(path)
    with pytest.raises(ForecastDataError, match='identity_mismatch'):
        Journal(path).configure('workspace', enabled=True)
    assert path.read_bytes() == before


def test_capacity_stops_recording_without_deleting_previous_history(tmp_path, monkeypatch):
    from research.flow_forecast.recording import journal as module
    monkeypatch.setattr(module, 'MAX_RECORDS', 2)
    journal = configured(tmp_path)
    item = request()
    for at in (1000, 1001):
        fresh = replace(item, created_at=at)
        assert journal.enqueue(fresh, current=fresh.binding, now=at) == 'pending'
    fresh = replace(item, created_at=1002)
    assert journal.enqueue(fresh, current=fresh.binding, now=1002) == 'recording_capacity_exceeded'
    assert len(journal.history('workspace')) == 2
