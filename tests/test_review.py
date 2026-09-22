import pytest

from tooluseproxy.engine.graph import GraphUnavailable
from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.property_graph import analyze_properties, validate
from tooluseproxy.engine.review import review


def verdict(dependencies=(), complete=True):
    return dict(
        externality="external",
        complete=complete,
        reason="fixture",
        accesses=[],
        dependencies=[dict(node_id=node, reason="fixture") for node in dependencies],
    )


def test_all_batches_are_reviewed_and_incomplete_tail_is_not_silently_dropped(tmp_path):
    prior = [dict(node_id=f"n{i}", completed=True, input="x" * 800, output="") for i in range(12)]
    calls = []

    def judge(records):
        calls.append(records["history_scope"]["index"])
        ids = [node["node_id"] for node in records["previous_calls"]]
        return verdict(ids, complete="n11" not in ids)

    result = review(
        tmp_path / "events.db",
        "revision",
        dict(current_call={"node_id": "current"}, previous_calls=prior),
        judge,
        validate,
        request_bytes=6000,
    )
    assert len(calls) > 1 and result["complete"] is False
    assert {item["node_id"] for item in result["dependencies"]} == {
        node["node_id"] for node in prior
    }


def test_batch_results_resume_after_failure_without_repeating_finished_work(tmp_path):
    prior = [dict(node_id=f"n{i}", completed=True, input="x" * 800) for i in range(8)]
    records = dict(current_call={"node_id": "current"}, previous_calls=prior)
    seen = []

    def fails(request):
        seen.append(request["history_scope"]["index"])
        if len(seen) == 2:
            raise TimeoutError()
        return verdict()

    with pytest.raises(TimeoutError):
        review(tmp_path / "events.db", "revision", records, fails, validate, request_bytes=6000)
    recovered = []
    result = review(
        tmp_path / "events.db",
        "revision",
        records,
        lambda request: (recovered.append(request["history_scope"]["index"]) or verdict()),
        validate,
        request_bytes=6000,
    )
    assert result["complete"] and 0 not in recovered and 1 in recovered


def test_single_oversized_record_is_not_truncated_into_a_negative(tmp_path):
    with pytest.raises(GraphUnavailable, match="single_call"):
        review(
            tmp_path / "events.db",
            "revision",
            dict(current_call={"input": "x" * 8000}, previous_calls=[]),
            lambda _: verdict(),
            validate,
            request_bytes=6000,
        )


def test_large_history_above_old_limits_still_checks_first_and_last_sources(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    store = Journal(tmp_path / "events.db")
    store.initialize()

    def record(call, phase, data):
        event = event_from(
            phase,
            dict(
                cwd=str(root),
                session_id="s",
                tool_use_id=call,
                tool_name="fixture",
                tool_input=data,
            ),
            str(root),
        )
        store.record(event)
        return event

    for index in range(80):
        for phase in ("pre_tool_use", "post_tool_use"):
            record(str(index), phase, {"i": index, "padding": "x" * 8000})
    for index in range(400):
        record(f"noise-{index}", "pre_tool_use", {"noise": True})
    partition_calls = []

    def judge(records):
        current = records["current_call"]["input"]
        if records.get("history_scope"):
            partition_calls.append(records["history_scope"])
        if current.get("send"):
            nodes = [
                node["node_id"]
                for node in records["previous_calls"]
                if node["completed"] and node["input"].get("i") in (0, 79)
            ]
            return verdict(nodes)
        return dict(
            externality="local",
            complete=True,
            reason="fixture",
            dependencies=[],
            accesses=[dict(path="private", mode="read", reason="fixture")]
            if current.get("i") == 0
            else [],
        )

    event = record("send", "pre_tool_use", {"send": True})
    result = analyze_properties(
        store.db_path,
        event.workspace_id,
        "s",
        event.event_id,
        [dict(node_id="source:p", path="private")],
        judge,
    )
    assert result["action"] == "block" and result["path"][0] == "source:p"
    assert partition_calls and all(item["count"] >= 2 for item in partition_calls)
