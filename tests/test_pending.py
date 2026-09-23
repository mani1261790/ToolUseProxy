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


def test_missing_evidence_does_not_schedule_unchanged_background_retry(tmp_path):
    from tooluseproxy.engine.pending import resume
    db = tmp_path / 'events.db'
    result = decide(db, event(), lambda _: dict(
        action='unavailable', reason='property_graph_incomplete', retryable=False))
    assert result['action'] == 'pending'
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT state,attempts FROM pending_judgments').fetchone() == (
            'needs_evidence', 1)
    assert resume(db, 'w', now=10**12, operation=lambda *_: 1/0) == 0
    # An explicit new delivery may bring new evidence and must be evaluated.
    assert decide(db, event(), lambda _: dict(action='allow', reason='new_evidence'))['action'] == 'allow'


def test_resume_judges_saved_event_but_never_runs_its_command(tmp_path):
    from tooluseproxy.app import main
    from tooluseproxy.engine.journal import Journal, event_from
    from tooluseproxy.engine.pending import resume, status
    root = tmp_path/'workspace'
    root.mkdir()
    data = tmp_path/'data'
    assert main(['setup', '--workspace', str(root), '--data-dir', str(data),
                 '--accept-judge-data', '--no-viewer', '--json']) == 0
    store = Journal(data/'events.db')
    sentinel = root/'must-not-execute'
    observed = event_from('pre_tool_use', dict(cwd=str(root), session_id='s',
        tool_use_id='t', tool_name='Bash', tool_input={'command': f'touch {sentinel}'}), str(root))
    store.record(observed)
    decide(store.db_path, observed, lambda _: {'action':'unavailable','reason':'offline'},
           sleep=lambda _:None)
    calls = []
    def recovered(event, deadline):
        calls.append(event.event_id)
        return {'action':'allow','reason':'fixture'}
    assert resume(store.db_path, observed.workspace_id, now=10**12, operation=recovered) == 1
    assert calls == [observed.event_id] and not sentinel.exists()
    assert status(store.db_path, observed.workspace_id) == {'complete':1}
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute('SELECT held FROM pending_judgments').fetchone()[0] == 1


def test_non_due_pending_does_not_call_model(tmp_path):
    from tooluseproxy.engine.pending import resume
    db = tmp_path/'events.db'
    decide(db, event(), lambda _: {'action':'unavailable','reason':'offline'}, sleep=lambda _:None)
    assert resume(db, 'w', now=0, operation=lambda *_: (_ for _ in ()).throw(AssertionError())) == 0


def test_concurrent_delivery_waits_then_revalidates_without_in_flight_duplication(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    db = tmp_path/'events.db'
    started, release, revalidated = Event(), Event(), Event()
    def operation(_):
        started.set()
        assert release.wait(5)
        return {'action':'allow','reason':'complete'}
    with ThreadPoolExecutor() as pool:
        first = pool.submit(decide, db, event(), operation)
        assert started.wait(5)
        def changed_policy(_):
            assert release.is_set()
            revalidated.set()
            return {'action': 'block', 'reason': 'policy changed'}
        second = pool.submit(decide, db, event(), changed_policy)
        try:
            assert not revalidated.wait(0.15)
            assert not second.done()
        finally:
            release.set()
        assert first.result()['action'] == 'allow'
        assert second.result()['action'] == 'block'
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT COUNT(*) FROM judgment_attempts').fetchone()[0] == 2


def test_stale_owner_cannot_publish_a_decision(tmp_path):
    db = tmp_path/'events.db'
    def operation(_):
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE pending_judgments SET owner='replacement'")
        return {'action':'allow','reason':'late'}
    result = decide(db, event(), operation)
    assert result['action'] == 'pending' and result['reason'] == 'judgment_ownership_changed'


def test_resume_respects_inactive_authority(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from tooluseproxy.engine.pending import resume
    db = tmp_path/'events.db'
    decide(db, event(), lambda _: {'action':'unavailable','reason':'offline'}, sleep=lambda _:None)
    @contextmanager
    def stopped(*_):
        yield SimpleNamespace(phase='inactive')
    monkeypatch.setattr('tooluseproxy.integrations.authority.registered_workspace_authority_lease', stopped)
    assert resume(db, 'w', now=10**12,
                  operation=lambda *_: (_ for _ in ()).throw(AssertionError())) == 0
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT state,attempts FROM pending_judgments').fetchone() == ('waiting',3)


def test_persisted_outage_resumes_through_real_runtime_pipeline(tmp_path):
    from tooluseproxy.app import main
    from tooluseproxy.engine.journal import Journal, event_from
    from tooluseproxy.engine.pending import resume
    root = tmp_path/'workspace'
    root.mkdir()
    data = tmp_path/'data'
    assert main(['setup','--workspace',str(root),'--data-dir',str(data),
                 '--accept-judge-data','--no-viewer','--json']) == 0
    store = Journal(data/'events.db')
    observed = event_from('pre_tool_use',dict(cwd=str(root),session_id='s',tool_use_id='send',
        tool_name='Bash',tool_input={'command':'send public data'}),str(root))
    store.record(observed)
    decide(store.db_path, observed, lambda _: {'action':'unavailable','reason':'offline'},
           sleep=lambda _:None)
    stages = []
    def judge(records):
        stages.append(records.get('stage','provenance'))
        return {'externality':'external','complete':True,'reason':'fixture',
                'dependencies':[],'accesses':[]}
    assert resume(store.db_path, observed.workspace_id, provider=judge, now=10**12) == 1
    assert stages == []  # The current empty policy now completes mechanically.
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute('SELECT state,attempts,held FROM pending_judgments').fetchone() == ('complete',4,1)
        assert conn.execute('SELECT action FROM semantic_flow_decisions').fetchone()[0] == 'allow'
        assert conn.execute("SELECT COUNT(*) FROM events WHERE phase='post_tool_use'").fetchone()[0] == 0


def test_missing_evidence_does_not_repeat_identical_foreground_judgments(tmp_path):
    calls=[]
    def operation(_):
        calls.append(1)
        return dict(action='unavailable',reason='property_graph_incomplete',retryable=False,
                    evidence_needs=[{'reason':'definition unavailable'}])
    result=decide(tmp_path/'events.db',event(),operation,sleep=lambda _:None)
    assert result['action']=='pending' and len(calls)==1
    assert result['evidence_needs']
