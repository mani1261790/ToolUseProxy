import copy

import pytest

from research.local_dependencies import Ledger, expand_compact, validate
from scripts.evaluate_local_dependencies import evaluate, summarize


def fixture():
    packet = dict(sources=[dict(id="a", text="private rule"), dict(id="b", text="public notice")],
                  outputs=[dict(id="x", text="derived rule"), dict(id="y", text="public notice")])
    rows = [dict(source_id=s["id"], output_id=o["id"], dependent=(s["id"], o["id"]) in
                 {("a", "x"), ("b", "y")}, score=0.7, reason="fixture")
            for s in packet["sources"] for o in packet["outputs"]]
    for row in rows:
        row["source_quote"] = next(s["text"] for s in packet["sources"] if s["id"] == row["source_id"]) if row["dependent"] else ""
        row["output_quote"] = next(o["text"] for o in packet["outputs"] if o["id"] == row["output_id"]) if row["dependent"] else ""
    return packet, dict(assessments=rows)


def ledger():
    result = Ledger()
    packet, review = fixture()
    for s in packet["sources"]:
        result.observe(s["id"], s["id"], s["text"])
    result.derive(packet, review, dict(x="report", y="report"))
    return result


def test_scoped_outputs_long_transfers_rename_and_late_registration():
    state = ledger()
    assert state.inspect("x", [])['action'] == "allow"
    assert state.inspect("x", ["a"])['action'] == "block"
    assert state.inspect("y", ["a"])['action'] == "allow"
    assert state.inspect("y", ["report"])['action'] == "block"
    path = state.inspect("x", ["a"])["paths"]["a"]
    assert [step["value_id"] for step in path] == ["a", "x"]
    assert path[0]["evidence"] == "observed_source"
    assert path[1]["evidence"]["kind"] == "model_inference"
    assert path[1]["evidence"]["assessments"][0]["score"] == 0.7
    parent = "x"
    for i in range(100):
        child = f"copy{i}"
        state.transfer(child, child, parent, "derived rule", observed_success=True)
        parent = child
    state.move("a", "renamed.md", observed_success=True)
    assert state.inspect(parent, ["a"])['action'] == "block"
    # Removing registration changes policy without rewriting the original evidence.
    assert state.inspect(parent, [])['action'] == "allow"


def test_equal_hash_is_not_origin_and_replacement_is_a_new_version():
    state = ledger()
    state.observe("independent", "elsewhere", "derived rule")
    assert state.values["independent"]["content_hash"] == state.values["x"]["content_hash"]
    assert state.inspect("independent", ["a"])['action'] == "allow"
    packet = dict(sources=[dict(id="b", text="public notice")],
                  outputs=[dict(id="replacement", text="public notice")])
    row = dict(source_id="b", output_id="replacement", dependent=True, score=0.9,
               reason="replacement supplied independently", source_quote="public notice",
               output_quote="public notice")
    state.derive(packet, dict(assessments=[row]), dict(replacement="report"))
    assert state.inspect("replacement", ["a"])['action'] == "allow"
    assert state.inspect("x", ["a"])['action'] == "block"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "nan", "invented", "unknown"])
def test_invalid_evidence_cannot_become_an_independent_output(mutation):
    packet, review = fixture()
    if mutation == "missing":
        review["assessments"].pop()
    elif mutation == "duplicate":
        review["assessments"].append(copy.deepcopy(review["assessments"][0]))
    elif mutation == "nan":
        review["assessments"][0]["score"] = float("nan")
    elif mutation == "invented":
        review["assessments"][0]["source_quote"] = "not observed"
    else:
        review["assessments"][0]["source_id"] = "not observed"
    with pytest.raises(ValueError):
        validate(packet, review)


def test_incomplete_review_does_not_mutate_ledger():
    packet, review = fixture()
    state = Ledger()
    for source in packet["sources"]:
        state.observe(source["id"], source["id"], source["text"])
    review["assessments"].pop()
    with pytest.raises(ValueError):
        state.derive(packet, review, dict(x="report", y="report"))
    assert set(state.values) == {"a", "b"}
    with pytest.raises(KeyError):
        state.inspect("x", ["a"])


def test_compact_response_preserves_rejected_candidates_and_positive_evidence():
    packet, review = fixture()
    compact = dict(assessments=[r for r in review["assessments"] if r["dependent"]],
                   independent=[{k: r[k] for k in ("output_id", "source_id", "score")}
                                for r in review["assessments"] if not r["dependent"]])
    expanded = expand_compact(packet, compact)
    assert len(expanded["assessments"]) == 4
    compact["independent"].pop()
    with pytest.raises(ValueError, match="missing_pairs"):
        expand_compact(packet, compact)


def test_failed_or_changed_transfer_is_not_observed():
    state = ledger()
    with pytest.raises(ValueError):
        state.move("a", "elsewhere", observed_success=False)
    with pytest.raises(ValueError):
        state.transfer("z", "z", "x", "changed content", observed_success=True)
    assert "z" not in state.values


def test_failed_classifier_is_reported_as_error_not_successful_block():
    packet, _ = fixture()
    case = dict(name="failure", packet=packet, parents=dict(x=["a"], y=["b"]), protected=["a"])

    def failed(_):
        raise TimeoutError("synthetic provider failure")

    result = evaluate(case, failed)
    assert result["status"] == "error" and not result["decisions_correct"]
    summary = summarize([result])
    assert summary["errors"] == 1 and summary["correct_decision_cases"] == 0
