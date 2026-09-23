import sqlite3

import pytest

from tooluseproxy.engine.evidence import EvidenceStore
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.payload import PayloadResolver, ResolutionError


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    root = root.resolve()
    db = tmp_path / "events.db"
    journal = Journal(db)
    journal.initialize()

    def make(session="one"):
        event = event_from(
            "pre_tool_use",
            dict(
                cwd=str(root),
                session_id=session,
                tool_use_id="send",
                tool_name="generic-tool",
                tool_input={"body": "hello", "attachment": "data.bin"},
            ),
            str(root),
        )
        journal.record(event)
        return PayloadResolver(EvidenceStore(db), event.workspace_id, event.event_id, root)

    return root, make


def file_target(path, offset=0, length=None):
    return dict(kind="file", path=path, offset=offset, length=length)


def test_observed_output_value_has_exact_extent_and_producer_identity(setup):
    _, make = setup
    resolver = make()
    resolver.observed_calls = ({'node_id': 'call:producer', 'event_id': 'post:producer',
                                'completed': True, 'output': {'value': 'PUBLIC PRIVATE'}},)
    result = resolver.resolve(dict(kind='observed', pointer='/previous_calls/0/output/value',
                                   offset=0, length=6))
    assert result.coverage == 'complete'
    assert result.parts[0].content == b'PUBLIC'
    assert result.parts[0].version.resource.kind == 'event_output'
    assert result.parts[0].observation['source_node_id'] == 'call:producer'


@pytest.mark.parametrize('pointer', ['/previous_calls/0/input', '/previous_calls/8/output',
                                     '/tool_input/body', '/previous_calls/0/output/missing'])
def test_observed_target_cannot_select_unprovided_records_or_inputs(setup, pointer):
    _, make = setup
    resolver = make()
    resolver.observed_calls = ({'completed': True, 'output': {'value': 'content'}},)
    result = resolver.resolve(dict(kind='observed', pointer=pointer, offset=0, length=None))
    assert result.coverage != 'complete' and not result.parts


def test_inline_comes_from_actual_input_and_does_not_store_plaintext(setup):
    root, make = setup
    resolver = make()
    target = {"kind": "inline", "pointer": "/tool_input/body"}
    result = resolver.resolve(target)
    assert result.coverage == "complete" and result.parts[0].content == b"hello"
    assert "hello" not in repr(result)
    resolver.persist(target, {"boundary": "external"}, result)
    with sqlite3.connect(resolver.store.path) as conn:
        row = conn.execute("SELECT token FROM flow_versions").fetchone()
        assert row and row[0] != "hello"
        assert (
            "hello"
            not in conn.execute("SELECT description_json FROM flow_transmissions").fetchone()[0]
        )
    with pytest.raises(ResolutionError, match="input_evidence_mismatch"):
        resolver.resolve(target, {"tool_input": {"body": "fabricated"}})


def test_version_identity_survives_sessions_and_extent_is_exact(setup):
    root, make = setup
    (root / "data.bin").write_bytes(b"private-public")
    first = make().resolve(file_target("data.bin", 8, 6))
    second = make("two").resolve(file_target("data.bin", 8, 6))
    assert first.parts[0].content == b"public"
    assert first.parts[0].version.identity == second.parts[0].version.identity
    (root / "data.bin").write_bytes(b"changed-public")
    third = make("three").resolve(file_target("data.bin"))
    assert third.parts[0].version.identity != first.parts[0].version.identity


def test_missing_collection_member_preserves_partial_coverage(setup):
    root, make = setup
    (root / "one").write_text("one")
    resolver = make()
    target = {
        "kind": "collection",
        "complete": True,
        "members": [file_target("one"), file_target("missing")],
    }
    result = resolver.resolve(target)
    assert result.coverage == "partial" and len(result.parts) == 1 and result.needs
    resolver.persist(target, {}, result)
    with sqlite3.connect(resolver.store.path) as conn:
        assert conn.execute("SELECT coverage FROM flow_resolutions").fetchone()[0] == "partial"
        assert conn.execute("SELECT COUNT(*) FROM flow_needs").fetchone()[0] == 1


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "protected_sources.json", "./one"])
def test_unsafe_references_never_open_files(setup, monkeypatch, path):
    _, make = setup
    resolver = make()
    monkeypatch.setattr("os.open", lambda *a, **kw: pytest.fail("must reject before opening"))
    result = resolver.resolve(file_target(path))
    assert result.coverage == "unsupported" and not result.parts


def test_symlink_and_fifo_are_not_followed(setup):
    import os

    root, make = setup
    (root / "outside-link").symlink_to(root.parent)
    os.mkfifo(root / "pipe")
    resolver = make()
    for path in ("outside-link/anything", "pipe"):
        assert resolver.resolve(file_target(path)).coverage == "unsupported"


def test_changed_resource_requires_reinspection(setup):
    root, make = setup
    (root / "file").write_text("original")
    resolver = make()
    result = resolver.resolve(file_target("file"))
    assert resolver.unchanged(result)
    (root / "file").write_text("changed!")
    assert not resolver.unchanged(result)


def test_missing_behavior_requests_evidence_without_executing(setup):
    _, make = setup
    result = make().resolve({"kind": "transform", "description": "arbitrary behavior"})
    assert result.coverage == "unsupported"
    assert result.needs[0].kind == "execution_definition"


def test_cumulative_budget_and_empty_collection_are_distinct(setup):
    root, make = setup
    resolver = make()
    resolver.max_bytes = 5
    (root / "one").write_bytes(b"1234")
    target = {
        "kind": "collection",
        "complete": True,
        "members": [file_target("one"), file_target("one")],
    }
    assert resolver.resolve(target).coverage == "partial"
    empty = resolver.resolve({"kind": "collection", "complete": True, "members": []})
    assert empty.coverage == "complete" and not empty.parts


def test_target_contract_never_turns_unknown_members_into_empty_complete():
    from tooluseproxy.engine.targets import validate_targets

    base = dict(pointer=None, path=None, offset=0, length=None, reason="missing definition")
    value = dict(complete=True, reason="fixture", targets=[dict(base, kind="unresolved")])
    target = validate_targets(value)
    assert target["complete"] is False and target["members"]
    value["targets"][0] = dict(base, kind="inline", pointer="/tool_output")
    with pytest.raises(ValueError):
        validate_targets(value)


def test_declared_nontransmitted_input_is_not_inspected(setup):
    from tooluseproxy.engine.targets import validate_targets

    _, make = setup
    target = validate_targets(
        dict(
            complete=True,
            reason="body only",
            targets=[
                dict(
                    kind="inline",
                    pointer="/tool_input/body",
                    path=None,
                    offset=0,
                    length=None,
                    reason="body field",
                )
            ],
        )
    )
    result = make().resolve(target)
    assert [part.content for part in result.parts] == [b"hello"]


def test_plan_cache_does_not_cache_mutable_file_contents(setup):
    from tooluseproxy.engine.targets import inspect_transmission

    root, make = setup
    existing = make()
    (root / "data.bin").write_bytes(b"first")
    with sqlite3.connect(existing.store.path) as conn:
        raw = conn.execute(
            "SELECT payload_json FROM events WHERE event_id=?", (existing.event,)
        ).fetchone()[0]
    import json

    event = event_from("pre_tool_use", json.loads(raw), str(root))
    store = Journal(existing.store.path)
    queried = []

    def provider(records):
        queried.append(records)
        return dict(
            complete=True,
            reason="file",
            targets=[
                dict(
                    kind="file", path="data.bin", pointer=None, offset=0, length=None, reason="file"
                )
            ],
        )

    _, first, _ = inspect_transmission(store, event, provider)
    (root / "data.bin").write_bytes(b"second")
    _, second, _ = inspect_transmission(store, event, provider)
    assert len(queried) == 1
    assert first.parts[0].content == b"first" and second.parts[0].content == b"second"
    assert first.parts[0].version.identity != second.parts[0].version.identity


def test_missing_execution_definition_is_read_not_executed_and_rejudged(setup):
    from tooluseproxy.engine.targets import inspect_transmission
    import json

    root, make = setup
    existing = make()
    (root / "behavior.txt").write_text("synthetic operation description")
    with sqlite3.connect(existing.store.path) as conn:
        raw = conn.execute(
            "SELECT payload_json FROM events WHERE event_id=?", (existing.event,)
        ).fetchone()[0]
    event = event_from("pre_tool_use", json.loads(raw), str(root))
    calls = []

    def provider(records):
        calls.append(len(records.get("execution_definitions", [])))
        if not records.get("execution_definitions"):
            return dict(
                complete=False,
                reason="definition required",
                targets=[
                    dict(
                        kind="unresolved",
                        path="behavior.txt",
                        pointer=None,
                        offset=0,
                        length=None,
                        reason="read definition",
                    )
                ],
            )
        assert records["execution_definitions"][0]["content"] == "synthetic operation description"
        return dict(
            complete=True,
            reason="body transmitted",
            targets=[
                dict(
                    kind="inline",
                    path=None,
                    pointer="/tool_input/body",
                    offset=0,
                    length=None,
                    reason="body",
                )
            ],
        )

    _, result, _ = inspect_transmission(Journal(existing.store.path), event, provider)
    assert result.coverage == "complete" and calls == [0, 1]
    assert result.parts[0].content == b"hello"


def test_inline_byte_extent_does_not_include_local_only_text(setup):
    _, make = setup
    result = make().resolve(dict(kind="inline", pointer="/tool_input/body", offset=1, length=3))
    assert result.parts[0].content == b"ell"
    assert result.parts[0].extent == {"offset": 1, "length": 3}


def repository_fixture(root):
    import subprocess
    def git(*args):
        return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL)
    git('init','-b','fixture')
    git('config','user.name','Fixture')
    git('config','user.email','fixture@example.invalid')
    return git


def test_repository_snapshot_reads_committed_history_not_current_files(setup):
    root,make=setup
    git=repository_fixture(root)
    (root/'note').write_text('original committed content')
    git('add','note')
    git('commit','-m','first')
    git('rm','note')
    git('commit','-m','delete')
    (root/'note').write_text('uncommitted replacement')
    resolver=make()
    target=dict(kind='snapshot',format='git',path='.',revision='HEAD')
    result=resolver.resolve(target)
    assert result.coverage=='complete'
    assert any(p.content==b'original committed content' for p in result.parts)
    assert not any(p.content==b'uncommitted replacement' for p in result.parts)
    assert {'commit','tree','blob'} <= {p.observation['object_kind'] for p in result.parts}
    assert resolver.unchanged(result)
    git('add','note')
    git('commit','-m','new')
    assert not resolver.unchanged(result)


def test_repository_snapshot_rejects_missing_revision_and_bounds_objects(setup):
    root,make=setup
    git=repository_fixture(root)
    (root/'note').write_text('fixture')
    git('add','note')
    git('commit','-m','first')
    resolver=make()
    for revision in ('--help','missing','HEAD:file'):
        assert resolver.resolve(dict(kind='snapshot',format='git',path='.',revision=revision)).coverage=='unsupported'
    resolver.max_members=1
    assert resolver.resolve(dict(kind='snapshot',format='git',path='.',revision='HEAD')).coverage=='unsupported'


def test_repository_snapshot_never_invokes_hooks_or_lazy_fetch(setup):
    root,make=setup
    git=repository_fixture(root)
    (root/'note').write_text('fixture')
    git('add','note')
    git('commit','-m','first')
    marker=root/'must-not-run'
    hook=root/'.git/hooks/pre-push'
    hook.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
    hook.chmod(0o700)
    resolver=make()
    assert resolver.resolve(dict(kind='snapshot',format='git',path='.',revision='HEAD')).coverage=='complete'
    assert not marker.exists()
    git('config','remote.fake.promisor','true')
    result=resolver.resolve(dict(kind='snapshot',format='git',path='.',revision='HEAD'))
    assert result.coverage=='unsupported' and result.needs[0].reason=='repository_requires_remote_objects'


def test_transmission_reuses_definition_evidence_but_not_graph_permission(setup):
    import json
    from tooluseproxy.engine.targets import inspect_transmission
    from tooluseproxy.engine.property_graph import schema, persist
    root, make = setup
    existing=make()
    (root/'behavior.txt').write_text('observed execution definition')
    with sqlite3.connect(existing.store.path) as conn:
        raw=conn.execute('select payload_json from events where event_id=?',(existing.event,)).fetchone()[0]
        event=event_from('pre_tool_use',json.loads(raw),str(root))
        schema(conn)
        persist(conn,event.workspace_id,event.session_id,{'node_id':'n','event_id':event.event_id},'r','model',
            {'complete':True,'externality':'external','reason':'not a permission certificate','dependencies':[],'accesses':[],
             'evidence_receipts':[{'path':'behavior.txt','reason':'needed definition','status':'observed','sha256':'earlier'}]})
    def provider(records):
        assert records['execution_definitions'][0]['content']=='observed execution definition'
        assert 'action' not in records and 'graph_verdict' not in records
        return {'complete':True,'reason':'recorded input','targets':[{'kind':'inline','pointer':'/tool_input/body','path':None,'offset':0,'length':None,'reason':'body'}]}
    resolver,resolution,_=inspect_transmission(Journal(existing.store.path),event,provider)
    assert resolution.coverage=='complete' and resolver.unchanged(resolution)
    (root/'behavior.txt').write_text('changed behavior')
    assert not resolver.unchanged(resolution)
