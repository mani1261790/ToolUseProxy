import sqlite3

import pytest

from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.lineage import snapshot_resources
from tooluseproxy.engine.property_graph import analyze_properties, bindings, persist, reach, schema


def make_history(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    root = root.resolve()
    (root / "private").write_text("Synthetic confidential source with coefficient 0.73")
    store = Journal(tmp_path / "events.db")
    store.initialize()

    def record(session, call, phase, step, resources=(), response=None):
        event = event_from(
            phase,
            dict(
                cwd=str(root),
                session_id=session,
                tool_use_id=call,
                tool_name="fixture",
                tool_input={"step": step},
                tool_response=response,
            ),
            str(root),
        )
        store.record(event)
        snapshot_resources(store, event, list(resources))
        return event

    record("a", "read", "pre_tool_use", "read", [{"path": "private", "mode": "read"}])
    record("a", "read", "post_tool_use", "read", response="coefficient 0.73")
    record("a", "write", "pre_tool_use", "write", [{"path": "derived", "mode": "write"}])
    (root / "derived").write_text("Apply a coefficient of seventy-three hundredths.")
    writer = record("a", "write", "post_tool_use", "write", response="done")
    return root, store, record, writer


@pytest.fixture
def history(tmp_path):
    return make_history(tmp_path)


def judge(records):
    step = records["current_call"]["input"]["step"]
    deps = []
    if step == "write":
        deps = [{"node_id": records["previous_calls"][0]["node_id"], "reason": "uses read result"}]
    return dict(
        externality="external" if step == "send" else "local",
        complete=True,
        reason="fixture",
        dependencies=deps,
        accesses=[
            dict(
                path="private" if step == "read" else "derived",
                mode="write" if step == "write" else "read",
                reason="fixture",
            )
        ],
    )


def inspect(store, event):
    return analyze_properties(
        store.db_path,
        event.workspace_id,
        event.session_id,
        event.event_id,
        [{"node_id": "source:private", "path": "private"}],
        judge,
    )


def test_observed_generation_links_sessions_and_expands_pending_producer(history):
    _, store, record, _ = history
    send = record("b", "send", "pre_tool_use", "send", [{"path": "derived", "mode": "read"}])
    result = inspect(store, send)
    assert result["action"] == "block" and len(result["path"]) == 4
    assert result["path"][0] == "source:private"
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM graph_heads WHERE session='a'").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM flow_file_observations").fetchone()[0] == 4


@pytest.mark.parametrize("same_content", [False, True])
def test_unobserved_replacement_never_inherits_old_producer(history, same_content):
    root, store, record, _ = history
    previous = (root / "derived").read_text()
    replacement = root / "replacement"
    replacement.write_text(previous if same_content else "unrelated replacement")
    replacement.replace(root / "derived")
    send = record("b", "send", "pre_tool_use", "send", [{"path": "derived", "mode": "read"}])
    assert inspect(store, send)["path"] == []


def test_failed_write_is_not_a_producer(history):
    root, store, record, _ = history
    record("c", "failed", "pre_tool_use", "write", [{"path": "derived", "mode": "write"}])
    (root / "derived").write_text("different bytes from an unsuccessful operation")
    record("c", "failed", "post_tool_use", "write", response={"exit_code": 1})
    send = record("b", "send", "pre_tool_use", "send", [{"path": "derived", "mode": "read"}])
    assert inspect(store, send)["path"] == []


def test_old_decision_traverses_pinned_parent_revision(tmp_path):
    store = Journal(tmp_path / "events.db")
    store.initialize()
    base = dict(externality="local", complete=True, reason="fixture", dependencies=[], accesses=[])
    with sqlite3.connect(store.db_path) as conn:
        schema(conn)
        old = dict(base, accesses=[dict(path="private", mode="read", reason="old read")])
        persist(
            conn, "scope", "a", {"node_id": "parent", "event_id": "old"}, "old", "model", old, {}
        )
        child = dict(
            base,
            externality="external",
            dependencies=[dict(node_id="parent", reason="uses old read")],
        )
        persist(
            conn,
            "scope",
            "b",
            {"node_id": "child", "event_id": "send"},
            "child-rev",
            "model",
            child,
            {"parent": "old"},
        )
        persist(
            conn, "scope", "a", {"node_id": "parent", "event_id": "new"}, "new", "model", base, {}
        )
        roots, _ = bindings(conn, "scope", "b", [dict(node_id="secret", path="private")])
        assert reach(conn, "scope", "b", "child", roots) == ["secret", "parent", "child"]
        assert reach(conn, "other", "b", "child", roots) == []


def test_unrelated_incomplete_observation_does_not_poison_send(tmp_path, monkeypatch):
    import tooluseproxy.engine.property_graph as graph

    db = tmp_path / "events.db"
    Journal(db).initialize()
    calls = [
        dict(
            node_id="incomplete",
            event_id="one",
            tool_name="fixture",
            input={},
            output="",
            completed=True,
        ),
        dict(
            node_id="send",
            event_id="two",
            tool_name="fixture",
            input={},
            output=None,
            completed=False,
        ),
    ]
    monkeypatch.setattr(graph, "load_calls", lambda *args: calls)

    def classify(records):
        sending = records["current_call"]["node_id"] == "send"
        return dict(
            externality="external" if sending else "local",
            complete=sending,
            reason="independent" if sending else "missing unrelated input",
            dependencies=[],
            accesses=[],
        )

    assert graph.analyze_properties(db, "scope", "s", "two", [], classify)["action"] == "allow"


def test_committed_generation_links_to_recorded_writer(history):
    from test_payload import repository_fixture
    from tooluseproxy.engine.payload import PayloadResolver
    from tooluseproxy.engine.evidence import EvidenceStore
    root,store,record,_=history
    git=repository_fixture(root)
    git('add','derived')
    git('commit','-m','fixture derived')
    event=record('b','push','pre_tool_use','send')
    resolver=PayloadResolver(EvidenceStore(store.db_path),event.workspace_id,event.event_id,root)
    target=dict(kind='snapshot',format='git',path='.',revision='HEAD')
    resolution=resolver.resolve(target)
    assert resolution.coverage=='complete'
    resolver.persist(target,{},resolution)
    result=inspect(store,event)
    assert result['action']=='block' and result['path'][0]=='source:private'


def test_historical_committed_generation_does_not_silently_lose_known_origin(history):
    from test_payload import repository_fixture
    from tooluseproxy.engine.payload import PayloadResolver
    from tooluseproxy.engine.evidence import EvidenceStore
    root,store,record,_=history
    git=repository_fixture(root)
    git('add','derived')
    git('commit','-m','fixture derived')
    (root/'derived').unlink()
    event=record('b','push','pre_tool_use','send')
    resolver=PayloadResolver(EvidenceStore(store.db_path),event.workspace_id,event.event_id,root)
    target=dict(kind='snapshot',format='git',path='.',revision='HEAD')
    resolution=resolver.resolve(target)
    resolver.persist(target,{},resolution)
    assert resolution.coverage=='complete'
    result=inspect(store,event)
    assert result['action']=='block' and result['path'][0]=='source:private'


def test_changed_repository_ref_replaces_immutable_read_set(history):
    from test_payload import repository_fixture
    from tooluseproxy.engine.payload import PayloadResolver
    from tooluseproxy.engine.evidence import EvidenceStore
    root,store,record,_=history
    git=repository_fixture(root)
    git('add','derived')
    git('commit','-m','derived')
    event=record('b','push','pre_tool_use','send')
    resolver=PayloadResolver(EvidenceStore(store.db_path),event.workspace_id,event.event_id,root)
    target=dict(kind='snapshot',format='git',path='.',revision='HEAD')
    resolver.persist(target,{},resolver.resolve(target))
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM flow_immutable_reads').fetchone()[0] > 0
    git('checkout','--orphan','public-only')
    git('rm','-rf','.')
    (root/'public').write_text('public fixture')
    git('add','public')
    git('commit','-m','public')
    resolver.persist(target,{},resolver.resolve(target))
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute('SELECT path FROM flow_immutable_reads').fetchall() == [('public',)]


@pytest.mark.parametrize('send_session', ['a', 'b'])
def test_external_resource_generation_preserves_protected_origin(tmp_path, send_session):
    root, store, record, writer = make_history(tmp_path)
    external=(tmp_path/'outside.txt').resolve()
    record('a','outside-write','pre_tool_use','outside-write',[{'path':str(external),'mode':'write'}])
    external.write_text('derived representation outside project')
    record('a','outside-write','post_tool_use','outside-write',response='done')
    send=record(send_session,'external-send','pre_tool_use','external-send',[{'path':str(external),'mode':'read'}])
    def external_judge(records):
        step=records['current_call']['input']['step']
        if step in ('outside-write','external-send'):
            deps=[] if step=='external-send' else [{'node_id':records['previous_calls'][0]['node_id'],'reason':'derived from private read'}]
            return dict(externality='external' if step=='external-send' else 'local',complete=True,
                        reason='fixture',dependencies=deps,accesses=[{'path':str(external),'mode':'read' if step=='external-send' else 'write','reason':'fixture'}])
        return judge(records)
    result=analyze_properties(store.db_path,send.workspace_id,send.session_id,send.event_id,
                              [{'node_id':'source:private','path':'private'}],external_judge)
    assert result['action']=='block' and result['path'][0]=='source:private'


@pytest.mark.parametrize('stale', ['prompt', 'model', 'incomplete'])
def test_cross_session_producer_is_reassessed_when_cached_judgment_is_stale(history, stale):
    import json
    _,store,record,writer=history
    inspect(store,writer)
    with sqlite3.connect(store.db_path) as conn:
        if stale=='incomplete':
            for revision,raw in conn.execute('select revision,verdict from graph_revisions').fetchall():
                value=json.loads(raw);value['complete']=False
                conn.execute('update graph_revisions set verdict=? where revision=?',(json.dumps(value),revision))
        else:
            conn.execute('update graph_revisions set '+stale+"='previous-version'")
        # Simulate a stored generation from an earlier runtime, without its cache.
        conn.execute('delete from graph_completed_reviews')
    send=record('new-session','send','pre_tool_use','send',[{'path':'derived','mode':'read'}])
    seen=[]
    def tracking(records):
        seen.append(records['current_call']['input']['step'])
        return judge(records)
    result=analyze_properties(store.db_path,send.workspace_id,send.session_id,send.event_id,
        [{'node_id':'source:private','path':'private'}],tracking)
    assert result['action']=='block'
    assert 'write' in seen and 'read' in seen
