import sqlite3
from dataclasses import replace

import pytest

from tooluseproxy.engine.evidence import ContentVersion, EvidenceNeed, EvidenceStore, Resource
from tooluseproxy.engine.journal import Journal, event_from


@pytest.fixture
def ledger(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    db = tmp_path / "events.db"
    journal = Journal(db)
    journal.initialize()
    events = []
    for session, call, phase in [
        ("a", "write", "pre_tool_use"),
        ("a", "write", "post_tool_use"),
        ("b", "send", "pre_tool_use"),
    ]:
        event = event_from(
            phase,
            dict(
                cwd=str(root),
                session_id=session,
                tool_use_id=call,
                tool_name="fixture",
                tool_input={},
            ),
            str(root),
        )
        journal.record(event)
        events.append(event)
    return EvidenceStore(db), journal, events


def version(events, index=1, token="version-1"):
    event = events[index]
    return ContentVersion(
        Resource(event.workspace_id, "file", "document"), token, event.event_id, 10
    )


def test_versions_survive_restart_and_sessions_without_merging_overwrites(ledger):
    store, journal, events = ledger
    first = version(events)
    assert store.add_version(first) == store.add_version(first)
    same = version(events, 2)
    assert store.add_version(same) == first.identity
    second = version(events, token="version-2")
    assert store.add_version(second) != first.identity
    journal.initialize()
    reopened = EvidenceStore(store.path)
    reopened.initialize()
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM flow_versions").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM flow_version_evidence").fetchone()[0] == 3
    with pytest.raises(ValueError, match="conflicting"):
        store.add_version(replace(first, byte_length=12))


def test_foreign_scope_is_rejected_atomically(ledger):
    store, _, events = ledger
    item = version(events)
    bad = replace(item, resource=replace(item.resource, scope="other"))
    with pytest.raises(sqlite3.IntegrityError):
        store.add_version(bad)
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM flow_resources").fetchone()[0] == 0


def test_pending_access_cannot_be_observed(ledger):
    store, _, events = ledger
    pending = version(events, 0)
    store.add_version(pending)
    with pytest.raises(ValueError, match="unexecuted"):
        store.add_access(pending, "write", "observed", "inference", {}, "fixture")
    store.add_access(pending, "write", "planned", "inference", {}, "fixture")
    actual = version(events)
    store.add_version(actual)
    store.add_access(actual, "write", "observed", "observation", {}, "fixture")
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT status FROM flow_accesses ORDER BY status").fetchall() == [
            ("observed",),
            ("planned",),
        ]


def test_resolution_coverage_is_not_a_match_result(ledger):
    store, _, events = ledger
    value = version(events)
    store.add_version(value)
    scope = value.resource.scope
    unit = store.add_transmission(
        scope, events[-1].event_id, {"kind": "reference"}, {"boundary": "external"}
    )
    for coverage in ("complete", "partial", "unsupported", "failed"):
        store.add_resolution(
            scope, unit, "v1", coverage, "fixture", [], [(value.identity, {"whole": True})]
        )
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM flow_resolutions").fetchone()[0] == 4
    with pytest.raises(sqlite3.IntegrityError):
        store.add_resolution(scope, unit, "v1", "no_match", "fixture", [], [])


def test_needs_have_bounded_progress_and_immutable_attempt_history(ledger):
    store, _, events = ledger
    scope, event = events[-1].workspace_id, events[-1].event_id
    need = store.add_need(scope, event, EvidenceNeed("origin", "resource-1", "missing producer"))
    store.record_attempt(scope, need, "failed", ["evidence-v1"], "fixture")
    with pytest.raises(ValueError, match="not_progressing"):
        store.record_attempt(scope, need, "failed", ["evidence-v1"], "fixture")
    store.record_attempt(scope, need, "resolved", ["evidence-v2"], "fixture")
    with pytest.raises(ValueError, match="not_progressing"):
        store.record_attempt(scope, need, "resolved", ["evidence-v3"], "fixture")
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM flow_need_attempts").fetchone()[0] == 2


def test_migration_preserves_old_events_and_rejects_future_schema(ledger):
    store, _, events = ledger
    with sqlite3.connect(store.path) as conn:
        before = conn.execute("SELECT * FROM events ORDER BY sequence_no").fetchall()
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'flow_%'"
            )
        ]
        for table in tables:
            conn.execute(f"DROP TABLE {table}")
    store.initialize()
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT * FROM events ORDER BY sequence_no").fetchall() == before
        assert conn.execute("SELECT COUNT(*) FROM flow_observations").fetchone()[0] == 3
        conn.execute("UPDATE flow_schema SET version=999")
    with pytest.raises(ValueError, match="unsupported_flow_schema"):
        store.initialize()
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT version FROM flow_schema").fetchone()[0] == 999
