"""Fault injection must reach a real decision, not count a held call as success."""
import json
import sqlite3
from types import SimpleNamespace

import pytest

from tooluseproxy.engine.codex import JudgeProviderError
from tooluseproxy.engine.journal import Journal, Source, event_from
from tooluseproxy.engine.property_graph import validate
from tooluseproxy.engine.review import review


def assessment(*, complete=True, dependencies=(), accesses=()):
    return dict(externality="external", complete=complete, reason="synthetic assessment",
                dependencies=list(dependencies), accesses=list(accesses))


@pytest.mark.parametrize("derived", [False, True])
def test_live_pipeline_recovers_in_same_delivery_without_a_held_result(tmp_path, monkeypatch, derived):
    from tooluseproxy.engine import pending
    from tooluseproxy.engine.runtime import process_hook

    root = tmp_path / "workspace"
    root.mkdir()
    secret = "Synthetic confidential calibration coefficient is 0.73."
    (root / "private").write_text(secret)
    store = Journal(tmp_path / "events.db")
    store.initialize()

    def record(call, phase, data, output=None):
        event = event_from(phase, dict(cwd=str(root), session_id="s", tool_use_id=call,
                           tool_name="fixture", tool_input=data, tool_response=output), str(root))
        store.record(event)
        return event

    record("read", "pre_tool_use", {"path": "private"})
    record("read", "post_tool_use", {"path": "private"}, secret)
    body = "Set the pitch to seven tenths." if derived else "Take a name badge at reception."
    event = record("send", "pre_tool_use", {"body": body})
    source = Source("private", "private", "file", "secret", (), event.workspace_id, "private", None)
    monkeypatch.setattr(store, "list_protected_sources_for_workspace", lambda _: [source])
    (tmp_path / "semantic-flow.json").write_text(json.dumps({"workspaces": {
        event.workspace_id: dict(provider="codex_exec", send_recorded_content=True,
                                 failure_policy="wait_for_decision", mode="enforce")}}))
    decide = pending.decide
    monkeypatch.setattr(pending, "decide", lambda *a, **kw: decide(*a, **kw, sleep=lambda _: None))
    attempts, feedback = [], []

    def judge(records):
        current = records["current_call"]
        if "body" not in current["input"]:
            return assessment(accesses=[dict(path="private", mode="read", reason="observed read")])
        attempts.append(1)
        feedback.append(records.get("assessment_feedback"))
        if len(attempts) <= 4:
            return assessment(complete=False)
        parents = records["previous_calls"]
        edges = [dict(node_id=parents[0]["node_id"], reason="synthetic transformation")]
        return assessment(dependencies=edges if derived else [])

    result = process_hook(store, event, judge=judge,
        screening_judge=lambda _: dict(externality="external", complete=True, reason="explicit send"),
        target_judge=lambda _: dict(complete=True, reason="body", targets=[dict(kind="inline",
            pointer="/tool_input/body", path=None, offset=0, length=None, reason="body")]))
    assert len(attempts) == 5
    assert feedback[0] is None and all(feedback[1:])
    if derived:
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "依存経路" in result["hookSpecificOutput"]["permissionDecisionReason"]
    else:
        assert result == {}
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT state,attempts,held FROM pending_judgments").fetchone() == (
            "complete", 5, 0)
        action, path = conn.execute("SELECT action,path_json FROM semantic_flow_decisions "
                                    "WHERE event_id=?", (event.event_id,)).fetchone()
        assert action == ("block" if derived else "allow")
        assert bool(json.loads(path)) == derived
        assert conn.execute("SELECT COUNT(*) FROM events WHERE phase='post_tool_use'").fetchone()[0] == 1


def test_short_review_checkpoint_survives_a_later_provider_failure(tmp_path):
    db = tmp_path / "events.db"
    records = dict(current_call={"node_id": "child"}, previous_calls=[])
    assert review(db, "revision", records, lambda _: assessment(), validate)["complete"]
    parent = dict(current_call={"node_id": "parent"}, previous_calls=[])
    with pytest.raises(JudgeProviderError):
        review(db, "parent", parent,
               lambda _: (_ for _ in ()).throw(JudgeProviderError("codex_exec_timeout")), validate)
    # The downstream child assessment is complete even though its parent failed.
    assert review(db, "revision", records, lambda _: pytest.fail("checkpoint lost"), validate)["complete"]
    assert review(db, "parent", parent, lambda _: assessment(), validate)["complete"]


def test_invalid_checkpoint_is_repaired_and_changed_evidence_is_not_reused(tmp_path):
    db = tmp_path / "events.db"
    records = dict(current_call={"node_id": "child"}, previous_calls=[])
    calls = []
    def judge(_):
        calls.append(1)
        return assessment()
    review(db, "revision", records, judge, validate)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE graph_review_parts SET verdict='{}'")
    review(db, "revision", records, judge, validate)
    records["current_call"]["output"] = "changed"
    review(db, "revision", records, judge, validate)
    assert len(calls) == 3


def test_slow_model_gets_more_time_but_cannot_extend_hook_deadline(monkeypatch):
    from tooluseproxy.engine.judge import CodexSemanticJudge
    observed, elapsed = [], [0.0]
    monkeypatch.setattr("tooluseproxy.engine.judge.time.monotonic", lambda: elapsed[0])
    def process(argv, stdin, cwd, environment, timeout):
        observed.append(timeout)
        if len(observed) == 1:
            elapsed[0] += timeout
            raise JudgeProviderError("codex_exec_timeout")
        (cwd / "verdict.json").write_text(json.dumps(assessment()))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr("tooluseproxy.engine.judge._run_process", process)
    judge = CodexSemanticJudge(timeout=60)
    judge.deadline = 150
    with pytest.raises(JudgeProviderError):
        judge({})
    assert judge({})["complete"]
    assert observed == [60, 90]
    elapsed[0] = 150
    with pytest.raises(JudgeProviderError):
        judge({})
    assert len(observed) == 2


def test_continuing_outage_never_becomes_a_false_decision(tmp_path):
    from tooluseproxy.engine.pending import decide
    elapsed = [0.0]
    event = SimpleNamespace(event_id="e", workspace_id="w", session_id="s")
    result = decide(tmp_path / "events.db", event,
        lambda _: dict(action="unavailable", reason="property_graph_incomplete", retry_scope="review"),
        budget_seconds=10, clock=lambda: elapsed[0],
        sleep=lambda seconds: elapsed.__setitem__(0, elapsed[0] + seconds))
    # This is still an unmet availability requirement, NOT protection success.
    assert result["action"] not in ("allow", "block")


def test_completed_child_is_not_rejudged_when_ancestor_times_out(tmp_path):
    from tooluseproxy.engine.property_graph import analyze_properties
    store = Journal(tmp_path / "events.db")
    store.initialize()
    root = tmp_path / "workspace"
    root.mkdir()
    for tool, phase in (("read", "pre_tool_use"), ("read", "post_tool_use"), ("send", "pre_tool_use")):
        event = event_from(phase, dict(cwd=str(root), session_id="s", tool_use_id=tool,
            tool_name="fixture", tool_input={"action": tool}, tool_response="synthetic"), str(root))
        store.record(event)
    calls = []
    def judge(records):
        action = records["current_call"]["input"]["action"]
        calls.append(action)
        if action == "send":
            return assessment(dependencies=[dict(node_id=records["previous_calls"][0]["node_id"],
                                                  reason="observed contribution")])
        if calls.count("read") == 1:
            raise JudgeProviderError("codex_exec_timeout")
        return assessment(accesses=[dict(path="private", mode="read", reason="source")])
    args = (store.db_path, event.workspace_id, "s", event.event_id,
            [dict(node_id="source:private", path="private")], judge)
    with pytest.raises(JudgeProviderError):
        analyze_properties(*args)
    assert analyze_properties(*args)["action"] == "block"
    assert calls == ["send", "read", "read"]
    # Model identity changes invalidate both the graph and checkpoint reviews.
    assert analyze_properties(*args, model="changed-model")["action"] == "block"
    assert calls[-2:] == ["send", "read"]


def test_invalid_model_assessment_returns_to_repair_not_a_decision(tmp_path):
    from tooluseproxy.engine.review import ReviewRetry
    records = dict(current_call={"node_id": "child"}, previous_calls=[])
    with pytest.raises(ReviewRetry):
        review(tmp_path / "events.db", "revision", records, lambda _: {}, validate)
    def repaired(packet):
        assert packet["assessment_feedback"]["previous_reason"] == "invalid_property_verdict"
        return assessment()
    assert review(tmp_path / "events.db", "revision", records, repaired, validate)["complete"]
