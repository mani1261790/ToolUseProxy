import sqlite3

from research.provenance_candidates import CandidateIndex


def node(i, text, **extra):
    return dict(node_id=f"n{i}", event_id=f"e{i}", input={}, output=text,
                completed=True, **extra)


def test_old_japanese_evidence_is_retrieved_beyond_recent_window(tmp_path):
    calls = [node(0, "試作品のコイル間隔は十九ミリメートル")]
    calls += [node(i, f"unrelated status {i}") for i in range(1, 100)]
    with sqlite3.connect(tmp_path / "index.db") as conn:
        index = CandidateIndex(conn, "w", "s", calls)
        records = index.select(100, node(100, "コイルを取り付けて間隔を確認する"))
        ids = {n["node_id"] for n in records["previous_calls"]}
        assert "n0" in ids
        assert {f"n{i}" for i in range(95, 100)} <= ids
        assert len(ids) <= 13
        assert not records["history_scope"]["exhaustive"]


def test_mandatory_producers_are_not_dropped_by_retrieval_limit(tmp_path):
    calls = [node(i, f"unrelated {i}") for i in range(100)]
    current = node(100, "new wording", resource_origins=[
        dict(producer_event=f"e{i}") for i in range(20)])
    current["payload_observations"] = [dict(observation=dict(source_node_id="n30"))]
    with sqlite3.connect(tmp_path / "index.db") as conn:
        selected = CandidateIndex(conn, "w", "s", calls).select(100, current)
        ids = {n["node_id"] for n in selected["previous_calls"]}
        assert {f"n{i}" for i in range(20)} | {"n30"} <= ids


def test_candidates_do_not_cross_scope_or_include_future_calls(tmp_path):
    calls = [node(i, "common data") for i in range(20)]
    with sqlite3.connect(tmp_path / "index.db") as conn:
        CandidateIndex(conn, "other", "s", [node(999, "unique secret")])
        selected = CandidateIndex(conn, "w", "s", calls).select(8, node(8, "unique secret common"))
        assert all(int(n["node_id"][1:]) < 8 for n in selected["previous_calls"])


def test_index_updates_changed_observations_and_reuses_unchanged_rows(tmp_path):
    calls = [node(i, f"oldterm{i}") for i in range(20)]
    with sqlite3.connect(tmp_path / "index.db") as conn:
        CandidateIndex(conn, "w", "s", calls)
        changes = conn.total_changes
        CandidateIndex(conn, "w", "s", calls)
        assert conn.total_changes == changes
        calls[0]["output"] = "replacementterm"
        index = CandidateIndex(conn, "w", "s", calls)
        selected = index.select(20, node(20, "replacementterm"))
        assert "n0" in selected["history_scope"]["reasons"]
        assert conn.execute("SELECT count(*) FROM flow_candidate_search WHERE flow_candidate_search MATCH 'oldterm0'").fetchone()[0] == 0
