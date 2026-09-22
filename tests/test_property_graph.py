import json
import sqlite3

from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.property_graph import analyze_properties, reach, schema


def test_late_protection_reuses_edges_and_keeps_old_policy_result(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    db = tmp_path / "events.db"
    store = Journal(db)
    store.initialize()
    events = []
    for call, phase in [
        ("read", "pre_tool_use"),
        ("read", "post_tool_use"),
        ("send", "pre_tool_use"),
    ]:
        event = event_from(
            phase,
            {
                "cwd": str(root),
                "session_id": "s",
                "tool_use_id": call,
                "tool_name": "test",
                "tool_input": {"call": call},
                "tool_response": "synthetic",
            },
            str(root),
        )
        store.record(event, [])
        events.append(event)
    queries = []

    def judge(records):
        assert "sources" not in records
        queries.append(records)
        read = records["current_call"]["input"]["call"] == "read"
        return {
            "externality": "local" if read else "external",
            "complete": True,
            "reason": "fixture",
            "accesses": [{"path": "private.txt", "mode": "read", "reason": "fixture"}]
            if read
            else [],
            "dependencies": []
            if read
            else [{"node_id": records["previous_calls"][0]["node_id"], "reason": "derived"}],
        }

    event = events[-1]
    args = (db, event.workspace_id, "s", event.event_id)
    assert analyze_properties(*args, [], judge)["action"] == "allow"
    assert len(queries) == 2
    protected = [
        {"node_id": "source:new", "path": "private.txt", "selector": {"kind": "whole_file"}}
    ]
    result = analyze_properties(*args, protected, judge)
    assert result["action"] == "block" and result["path"][0] == "source:new"
    assert len(queries) == 2
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM graph_revisions").fetchone()[0] == 2
        decisions = [
            json.loads(row[0])["action"]
            for row in conn.execute("SELECT result FROM graph_policy_checks")
        ]
        assert decisions == ["allow", "block"]
        assert conn.execute('SELECT COUNT(*) FROM graph_policies').fetchone()[0] == 2
        assert conn.execute('SELECT COUNT(*) FROM graph_revision_links').fetchone()[0] == 1
        assert reach(conn, "another", "s", result["node_id"], {}) == []


def test_graph_indexes_and_cross_scope_traversal(tmp_path):
    with sqlite3.connect(tmp_path / "events.db") as conn:
        schema(conn)
        for workspace, node, revision in [
            ("a", "child", "r1"),
            ("a", "parent", "r2"),
            ("b", "other", "r3"),
        ]:
            conn.execute(
                "INSERT INTO graph_heads VALUES (?,?,?,?)", (workspace, "s", node, revision)
            )
        conn.execute("INSERT INTO graph_edges VALUES ('r1','parent','child','reason')")
        assert reach(conn, "a", "s", "child", {"parent": "source:p"}) == [
            "source:p",
            "parent",
            "child",
        ]
        assert reach(conn, "b", "s", "child", {"parent": "source:p"}) == []
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT src FROM graph_edges WHERE dst=? AND revision=?",
            ("child", "r1"),
        ).fetchall()
        assert any("INDEX" in row[3] for row in plan)


def test_changed_observation_preserves_both_revisions(tmp_path):
    from tooluseproxy.engine.property_graph import persist

    db = tmp_path / "events.db"
    node = {"node_id": "n", "event_id": "before"}
    verdict = {
        "dependencies": [],
        "accesses": [],
        "complete": True,
        "externality": "local",
        "reason": "test",
    }
    with sqlite3.connect(db) as conn:
        schema(conn)
        persist(conn, "w", "s", node, "r1", "model", verdict)
        node["event_id"] = "after"
        persist(conn, "w", "s", node, "r2", "model", verdict)
        assert conn.execute("SELECT COUNT(*) FROM graph_revisions").fetchone()[0] == 2
        assert conn.execute("SELECT revision FROM graph_heads").fetchone()[0] == "r2"
        before = conn.total_changes
        persist(conn, "w", "s", node, "r2", "model", verdict)
        assert conn.total_changes == before


def test_unknown_selectors_cannot_establish_complete_policy(tmp_path):
    from tooluseproxy.engine.property_graph import bindings, validate
    from tooluseproxy.engine.graph import GraphUnavailable
    import pytest

    with sqlite3.connect(tmp_path / "events.db") as conn:
        schema(conn)
        assert bindings(
            conn, "w", "s", [{"node_id": "p", "path": "x", "selector": {"kind": "lines"}}]
        ) == ({}, False)
    with pytest.raises(GraphUnavailable):
        validate(
            {
                "dependencies": [],
                "accesses": [{"path": "../outside", "mode": "read", "reason": "guess"}],
                "complete": True,
                "externality": "local",
                "reason": "test",
            },
            set(),
        )
