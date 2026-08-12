from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from hook_monitor.analysis.adapters.bash import classify_bash_sink_type
from hook_monitor.externality.envelope import analyze_bash_externality
from hook_monitor.runtime.externality_shadow import combine_externality_verdicts


GROUND_TRUTHS = frozenset({"external", "local"})


@dataclass(frozen=True)
class ExternalityJudgeCase:
    case_id: str
    command: str
    ground_truth: str


@dataclass(frozen=True)
class ExternalityJudgeCaseResult:
    case_id: str
    ground_truth: str
    adapter_verdict: str
    static_verdict: str
    judge_verdict: str
    combined_verdict: str


def evaluate_externality_judge_cases(
    cases: Iterable[ExternalityJudgeCase],
    *,
    workspace_root: Path,
    judge_verdicts: Mapping[str, str] | None = None,
) -> dict[str, object]:
    supplied_judgments = dict(judge_verdicts or {})
    results: list[ExternalityJudgeCaseResult] = []
    for case in cases:
        if case.ground_truth not in GROUND_TRUTHS:
            raise ValueError("externality case ground truth is invalid")
        static = analyze_bash_externality(
            case.command,
            workspace_root=workspace_root,
        )
        judge_verdict = supplied_judgments.get(case.case_id, "not_run")
        if static.verdict != "unknown":
            judge_verdict = "not_run"
        adapter_verdict = (
            "external"
            if classify_bash_sink_type(case.command) is not None
            else "unknown"
        )
        combined = combine_externality_verdicts(
            adapter_verdict,
            static.verdict,
            judge_verdict,
        )
        results.append(
            ExternalityJudgeCaseResult(
                case_id=case.case_id,
                ground_truth=case.ground_truth,
                adapter_verdict=adapter_verdict,
                static_verdict=static.verdict,
                judge_verdict=judge_verdict,
                combined_verdict=combined,
            )
        )
    external = [result for result in results if result.ground_truth == "external"]
    local = [result for result in results if result.ground_truth == "local"]
    false_local = sum(result.combined_verdict == "local" for result in external)
    adapter_external = sum(
        result.adapter_verdict == "external" for result in external
    )
    risky_external = sum(
        result.combined_verdict in {"external", "possibly_external", "unknown"}
        for result in external
    )
    false_risk = sum(
        result.combined_verdict in {"external", "possibly_external", "unknown"}
        for result in local
    )
    return {
        "schema_version": 1,
        "case_count": len(results),
        "external_count": len(external),
        "local_count": len(local),
        "false_local_count": false_local,
        "adapter_external_recall": _ratio(adapter_external, len(external)),
        "risk_recall": _ratio(risky_external, len(external)),
        "local_false_risk_rate": _ratio(false_risk, len(local)),
        "shadow_added_risk_count": sum(
            result.ground_truth == "external"
            and result.adapter_verdict != "external"
            and result.combined_verdict
            in {"external", "possibly_external", "unknown"}
            for result in results
        ),
        "privacy": {"raw_values_in_report": False},
        "production_behavior_changed": False,
        "cases": [
            {
                "id": result.case_id,
                "ground_truth": result.ground_truth,
                "adapter_verdict": result.adapter_verdict,
                "static_verdict": result.static_verdict,
                "judge_verdict": result.judge_verdict,
                "combined_verdict": result.combined_verdict,
            }
            for result in results
        ],
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)
