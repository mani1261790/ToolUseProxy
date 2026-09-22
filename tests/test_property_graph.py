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
        assert conn.execute("SELECT COUNT(*) FROM graph_policies").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM graph_revision_links").fetchone()[0] == 1
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


def test_history_chain_reuses_prefix_and_invalidates_changed_evidence(tmp_path, monkeypatch):
    import tooluseproxy.engine.property_graph as graph

    db = tmp_path / "events.db"
    calls = [
        dict(
            node_id=f"n{i}",
            event_id=f"e{i}",
            tool_name="test",
            input={"i": i},
            output="original",
            completed=True,
        )
        for i in range(3)
    ]
    monkeypatch.setattr(graph, "load_calls", lambda *args: calls)
    queried = []

    def judge(records):
        queried.append(records["current_call"]["node_id"])
        # Another writer can acquire the DB while a model request is running.
        with sqlite3.connect(db, timeout=0.1) as other:
            other.execute("BEGIN IMMEDIATE")
        return dict(
            externality="local", complete=True, reason="fixture", accesses=[], dependencies=[]
        )

    graph.analyze_properties(db, "w", "s", "e2", [], judge)
    assert queried == ["n0", "n1", "n2"]
    queried.clear()
    graph.analyze_properties(db, "w", "s", "e2", [], judge)
    assert queried == []
    calls.append(
        dict(node_id="n3", event_id="e3", tool_name="test", input={}, output="", completed=True)
    )
    graph.analyze_properties(db, "w", "s", "e3", [], judge)
    assert queried == ["n3"]
    queried.clear()
    calls[1]["output"] = "changed evidence"
    graph.analyze_properties(db, "w", "s", "e3", [], judge)
    assert queried == ["n1", "n2", "n3"]
    queried.clear()
    graph.analyze_properties(db, "w", "s", "e3", [], judge, model="other-model")
    assert queried == ["n0", "n1", "n2", "n3"]


def test_history_hash_input_grows_linearly(tmp_path, monkeypatch):
    import tooluseproxy.engine.property_graph as graph

    real_digest = graph.digest
    volumes = []
    for count in (40, 80):
        calls = [
            dict(
                node_id=f"n{i:03}",
                event_id=f"e{i:03}",
                tool_name="test",
                input={"text": "x" * 100},
                output="y" * 100,
                completed=True,
            )
            for i in range(count)
        ]
        monkeypatch.setattr(graph, "load_calls", lambda *args: calls)
        sizes = []

        def digest(value):
            sizes.append(len(json.dumps(value)))
            return real_digest(value)

        monkeypatch.setattr(graph, "digest", digest)
        graph.analyze_properties(
            tmp_path / f"{count}.db",
            "w",
            "s",
            calls[-1]["event_id"],
            [],
            lambda records: dict(
                externality="local", complete=True, reason="fixture", accesses=[], dependencies=[]
            ),
        )
        volumes.append(sum(sizes))
    assert 1.9 < volumes[1] / volumes[0] < 2.1
