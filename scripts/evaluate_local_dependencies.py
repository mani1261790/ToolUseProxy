"""Compare isolated model inference on synthetic inputs; never executes a send.

PYTHONPATH=. .venv/bin/python scripts/evaluate_local_dependencies.py --backend local
"""

import argparse
import json
from pathlib import Path
import statistics
import tempfile
import time

from research.dependency_cases import cases
from research.local_dependencies import Ledger, LocalJudge, VERSION, fingerprint, validate
from tooluseproxy.engine.judge import CodexSemanticJudge
from tooluseproxy.engine.property_graph import validate as validate_current


class CurrentJudge:
    """Current prompt on the same source/target texts, not the entire live runtime.

    Its schema reviews one selected output at a time. Quotes below are controller
    anchors for the adapter, not finer spans supplied by this baseline model.
    """

    def __init__(self, model=None, timeout=90):
        self.judge = CodexSemanticJudge(model=model, timeout=timeout)

    def __call__(self, packet):
        history = [dict(node_id=s["id"], event_id=s["id"], completed=True,
                        tool_name="read_file", input={"path": f'{s["id"]}.txt'},
                        output=s["text"], workspace_root="/synthetic", resolved_cwd="/synthetic")
                   for s in packet["sources"]]
        assessments = []
        for output in packet["outputs"]:
            current = dict(node_id=output["id"], event_id=output["id"], completed=False,
                           tool_name="http.post", input={"url": "https://example.invalid",
                                                         "body": output["text"]},
                           output=None, workspace_root="/synthetic", resolved_cwd="/synthetic")
            result = validate_current(self.judge(dict(previous_calls=history, current_call=current)),
                                      {s["id"] for s in packet["sources"]})
            if not result["complete"]:
                raise ValueError("baseline_incomplete")
            positive = {d["node_id"] for d in result["dependencies"]}
            paths = {f'{s["id"]}.txt': s["id"] for s in packet["sources"]}
            for access in result["accesses"]:
                if access["mode"] != "read" or access["path"] not in paths:
                    raise ValueError("baseline_unobserved_access")
                positive.add(paths[access["path"]])
            for source in packet["sources"]:
                dependent = source["id"] in positive
                assessments.append(dict(output_id=output["id"], source_id=source["id"],
                    dependent=dependent, score=0.5, reason=result["reason"],
                    source_quote=source["text"] if dependent else "",
                    output_quote=output["text"] if dependent else ""))
        return validate(packet, dict(assessments=assessments))


def evaluate(case, judge):
    started = time.monotonic()
    packet = case["packet"]
    item = dict(case=case["name"], input_hash=fingerprint(packet),
                source_count=len(packet["sources"]), output_count=len(packet["outputs"]))
    try:
        result = judge(packet)
        ledger = Ledger()
        for source in packet["sources"]:
            ledger.observe(source["id"], source["id"], source["text"])
        ledger.derive(packet, result, {o["id"]: o["id"] for o in packet["outputs"]})
        actual = {o["id"]: sorted(r["source_id"] for r in result["assessments"]
                  if r["output_id"] == o["id"] and r["dependent"]) for o in packet["outputs"]}
        expected = {o: sorted(parents) for o, parents in case["parents"].items()}
        decisions = {o["id"]: ledger.inspect(o["id"], case["protected"])["action"]
                     for o in packet["outputs"]}
        expected_decisions = {o: "block" if set(parents) & set(case["protected"]) else "allow"
                              for o, parents in expected.items()}
        pairs = [(r["dependent"], r["source_id"] in expected[r["output_id"]])
                 for r in result["assessments"]]
        item.update(status="complete", actual=actual, expected=expected,
                    edges_correct=actual == expected, decisions=decisions,
                    expected_decisions=expected_decisions,
                    decisions_correct=decisions == expected_decisions,
                    tp=sum(a and e for a, e in pairs), fp=sum(a and not e for a, e in pairs),
                    fn=sum(not a and e for a, e in pairs), tn=sum(not a and not e for a, e in pairs),
                    assessments=result["assessments"])
    except Exception as error:
        # An error stays in the denominator and never counts as a protected block.
        item.update(status="error", error_type=type(error).__name__, error=str(error),
                    edges_correct=False, decisions_correct=False)
    item["seconds"] = round(time.monotonic() - started, 3)
    return item


def summarize(rows):
    totals = {key: sum(r.get(key, 0) for r in rows) for key in ("tp", "fp", "fn", "tn")}
    complete = sum(r["status"] == "complete" for r in rows)
    return dict(cases=len(rows), completed=complete, errors=len(rows)-complete,
                exact_edge_cases=sum(r["edges_correct"] for r in rows),
                correct_decision_cases=sum(r["decisions_correct"] for r in rows),
                edge_counts_completed_only=totals,
                median_seconds=round(statistics.median(r["seconds"] for r in rows), 3),
                max_seconds=max(r["seconds"] for r in rows))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("local", "compact", "current"), required=True)
    parser.add_argument("--case", action="append", choices=[c["name"] for c in cases()])
    parser.add_argument("--model")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    path = args.output or Path(tempfile.mkdtemp(prefix="tup-local-evaluation-")) / "report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SystemExit("output already exists; choose a new report path")
    judge = (CurrentJudge(args.model, args.timeout) if args.backend == "current"
             else LocalJudge(args.model, args.timeout, compact=args.backend == "compact"))
    report = dict(version=VERSION, backend=args.backend, model=args.model or "codex_default",
                  outbound_executed=False, scope="synthetic development inference only; not live Hook",
                  ground_truth="author-labelled; not independent human review",
                  confidence="uncalibrated; baseline scores are placeholders and must not be evaluated",
                  cases=[])
    print(f"REPORT {path}", flush=True)
    for case in cases():
        if args.case and case["name"] not in args.case:
            continue
        item = evaluate(case, judge)
        report["cases"].append(item)
        report["summary"] = summarize(report["cases"])
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(json.dumps({k: v for k, v in item.items() if k != "assessments"}, ensure_ascii=False), flush=True)
    print(json.dumps(report["summary"], ensure_ascii=False), flush=True)
    if any(not r["edges_correct"] or not r["decisions_correct"] for r in report["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
