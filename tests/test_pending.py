import sqlite3
from types import SimpleNamespace

from tooluseproxy.engine.pending import decide


def event():
    return SimpleNamespace(event_id='e', workspace_id='w', session_id='s')


def test_transient_failure_finishes_before_returning_permission(tmp_path):
    db = tmp_path / 'events.db'
    calls = []
    def operation(deadline):
        calls.append(deadline)
        return dict(action='allow' if len(calls) == 2 else 'unavailable', reason='fixture')
    result = decide(db, event(), operation, sleep=lambda _: None)
    assert result['action'] == 'allow'
    assert len(calls) == 2 and calls[0] == calls[1]
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT state,attempts FROM pending_judgments').fetchone() == ('complete', 2)


def test_outage_is_retained_and_recovered_delivery_is_revalidated(tmp_path):
    db = tmp_path / 'events.db'
    result = decide(db, event(), lambda _: {'action': 'unavailable', 'reason': 'offline'}, sleep=lambda _: None)
    assert result['action'] == 'pending'
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT state,attempts FROM pending_judgments').fetchone() == ('waiting', 3)
    result = decide(db, event(), lambda _: {'action': 'allow', 'reason': 'recovered'})
    assert result['action'] == 'allow'
    # A later delivery must inspect changed resources rather than reuse allow.
    result = decide(db, event(), lambda _: {'action': 'block', 'reason': 'changed'})
    assert result['action'] == 'block'


def test_bad_result_never_grants_permission(tmp_path):
    result = decide(tmp_path/'events.db', event(), lambda _: {}, sleep=lambda _: None)
    assert result['action'] == 'pending'
