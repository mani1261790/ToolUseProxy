from __future__ import annotations

import hashlib
import json
import math
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from hook_monitor.analysis.bash_submission import extract_bash_http_submissions
from hook_monitor.analysis.chunking import build_source_chunks
from hook_monitor.analysis.leak_detection import LeakFinding, severity_for_score
from hook_monitor.analysis.similarity import (
    EmbeddingBackend,
    SimilarityDecision,
    compare_source_binding_text,
)
from hook_monitor.evaluation.sink_benchmark_dataset import (
    SinkBenchmarkCase,
    SinkBenchmarkDataset,
)
from hook_monitor.evaluation.source_ingestion import evaluate_source_ingestion
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.runtime.models import ProtectedSource, SourceChunk
from hook_monitor.runtime.normalize import normalize_text


RUNNER_VERSION = "sink-benchmark-v1"
PROFILE_DIRECT = "direct_lexical"
PROFILE_RESOLVED = "resolved_lexical"
PROFILE_SEMANTIC = "resolved_semantic"
PROFILE_LINEAGE = "lineage_assisted"
PROFILE_NAMES = (
    PROFILE_DIRECT,
    PROFILE_RESOLVED,
    PROFILE_SEMANTIC,
    PROFILE_LINEAGE,
)


def evaluate_sink_benchmark(
    dataset: SinkBenchmarkDataset,
    *,
    split: str | None = "development",
    embedding_backend: EmbeddingBackend | None = None,
) -> dict[str, Any]:
    """Compare sink-first detection profiles without executing a target tool."""
    cases = dataset.select_cases(split)
    if not cases:
        raise ValueError("sink benchmark selection must not be empty")

    selected_ingestion = replace(
        dataset.ingestion_dataset,
        scenarios=tuple(case.ingestion for case in cases),
    )
    lineage_report = evaluate_source_ingestion(selected_ingestion, split=None)
    lineage_by_id = {
        item["id"]: item for item in lineage_report["cases"]["scenarios"]
    }

    case_reports = [
        _evaluate_case(
            case,
            lineage_case=lineage_by_id[case.case_id],
            embedding_backend=embedding_backend,
        )
        for case in cases
    ]
    metrics = {
        profile: {
            "all": _profile_metrics(case_reports, profile, include_observe_only=True),
            "gate": _profile_metrics(case_reports, profile, include_observe_only=False),
        }
        for profile in PROFILE_NAMES
    }
    deltas = {
        "resolved_over_direct": _profile_delta(
            case_reports, PROFILE_DIRECT, PROFILE_RESOLVED
        ),
        "semantic_over_resolved": _profile_delta(
            case_reports, PROFILE_RESOLVED, PROFILE_SEMANTIC
        ),
        "lineage_over_resolved": _profile_delta(
            case_reports, PROFILE_RESOLVED, PROFILE_LINEAGE
        ),
    }
    report = {
        "schema_version": 1,
        "runner_version": RUNNER_VERSION,
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "sha256": dataset.digest_sha256,
            "split": split or "all",
            "case_count": len(cases),
        },
        "configuration": {
            "profiles": list(PROFILE_NAMES),
            "embedding_backend": (
                type(embedding_backend).__name__
                if embedding_backend is not None
                else None
            ),
            "network_execution": False,
            "target_tool_execution": False,
            "semantic_observe_only": True,
            "lineage_runner_version": lineage_report["runner_version"],
        },
        "metrics": metrics,
        "deltas": deltas,
        "lineage_reference": {
            "full_incremental_parity_passed": lineage_report["metrics"][
                "full_incremental_parity"
            ]["passed"],
            "quality_gate_passed": lineage_report["summary"][
                "quality_gate_passed"
            ],
        },
        "cases": case_reports,
    }
    privacy_exposure_ids = _privacy_exposure_ids(report, cases)
    report["privacy"] = {
        "raw_fixture_values_in_report": len(privacy_exposure_ids),
        "exposure_case_ids": privacy_exposure_ids,
    }
    report["summary"] = {
        "quality_gate_passed": (
            not privacy_exposure_ids
            and report["lineage_reference"]["full_incremental_parity_passed"]
            and all(
                case_report["profiles"][PROFILE_DIRECT]["status"] == "evaluated"
                for case_report in case_reports
            )
            and all(
                case_report["profiles"][PROFILE_RESOLVED]["status"]
                in {"evaluated", "unsupported"}
                for case_report in case_reports
            )
        ),
        "semantic_backend_available": embedding_backend is not None,
        "unsupported_resolved_case_ids": [
            case_report["id"]
            for case_report in case_reports
            if case_report["profiles"][PROFILE_RESOLVED]["status"]
            == "unsupported"
        ],
        "observe_only_case_count": sum(case.observe_only for case in cases),
    }
    return report


def render_sink_benchmark_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    lines = [
        (
            f"sink benchmark dataset={dataset['id']} version={dataset['version']} "
            f"split={dataset['split']} sha256={dataset['sha256'][:12]}"
        ),
        (
            f"cases={dataset['case_count']} "
            f"semantic_backend="
            f"{report['configuration']['embedding_backend'] or 'unavailable'}"
        ),
    ]
    for profile in PROFILE_NAMES:
        metric = report["metrics"][profile]["all"]
        reach = metric["detection"]
        lines.append(
            f"{profile} coverage={metric['coverage']['evaluated']}/"
            f"{metric['coverage']['total']} "
            f"precision={_format_ratio(reach['precision'])} "
            f"recall={_format_ratio(reach['recall'])} "
            f"f1={_format_ratio(reach['f1'])} "
            f"action_accuracy={_format_ratio(metric['action_accuracy'])}"
        )
    unsupported = report["summary"]["unsupported_resolved_case_ids"]
    lines.extend(
        (
            (
                "resolved unsupported="
                f"{','.join(unsupported) if unsupported else 'none'}"
            ),
            (
                "lineage parity="
                f"{'PASS' if report['lineage_reference']['full_incremental_parity_passed'] else 'FAIL'}"
            ),
            (
                "privacy raw_fixture_values_in_report="
                f"{report['privacy']['raw_fixture_values_in_report']}"
            ),
            (
                "foundation gate="
                f"{'PASS' if report['summary']['quality_gate_passed'] else 'FAIL'}"
            ),
        )
    )
    return "\n".join(lines)


def _evaluate_case(
    case: SinkBenchmarkCase,
    *,
    lineage_case: dict[str, Any],
    embedding_backend: EmbeddingBackend | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="tooluseproxy-sink-benchmark-"
    ) as temporary_directory:
        workspace = Path(temporary_directory) / "workspace"
        workspace.mkdir()
        source_path = workspace / case.ingestion.source.path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(case.ingestion.source.content, encoding="utf-8")
        source = ProtectedSource(
            source_id=case.ingestion.source.source_key,
            path=case.ingestion.source.path,
            source_type=case.ingestion.source.source_type,
            sensitivity=case.ingestion.source.sensitivity,
            policy_tags=case.ingestion.source.policy_tags,
            selector=case.ingestion.source.selector,
        )
        chunks = build_source_chunks(workspace, source)
        target_payload = case.ingestion.events[-1].payload
        direct_values = _direct_payload_values(case, target_payload)
        resolved_values, unsupported_reason = _resolved_payload_values(
            case, target_payload
        )

        direct = _evaluate_values(
            chunks,
            direct_values,
            case=case,
            embedding_backend=None,
        )
        if unsupported_reason is None:
            resolved = _evaluate_values(
                chunks,
                resolved_values,
                case=case,
                embedding_backend=None,
            )
        else:
            resolved = _profile_result(
                status="unsupported",
                detected=None,
                action=None,
                decision=None,
                payload_unit_count=0,
                unsupported_reason=unsupported_reason,
            )
        if embedding_backend is None:
            semantic = _profile_result(
                status="unavailable",
                detected=None,
                action=None,
                decision=None,
                payload_unit_count=(
                    len(resolved_values) if unsupported_reason is None else 0
                ),
                unsupported_reason="embedding_backend_not_configured",
            )
        elif unsupported_reason is not None:
            semantic = _profile_result(
                status="unsupported",
                detected=None,
                action=None,
                decision=None,
                payload_unit_count=0,
                unsupported_reason=unsupported_reason,
            )
        else:
            semantic = _evaluate_values(
                chunks,
                resolved_values,
                case=case,
                embedding_backend=embedding_backend,
            )

    lineage_detected = bool(lineage_case["actual_reach"])
    lineage = _profile_result(
        status="evaluated",
        detected=lineage_detected,
        action=lineage_case["actual_action"],
        decision=None,
        payload_unit_count=lineage_case["target_sink_count"],
        method="runtime_lineage" if lineage_detected else "none",
        score=lineage_case["path_score"],
    )
    return {
        "id": case.case_id,
        "split": case.split,
        "source_kind": case.source_kind,
        "transformation": case.transformation,
        "boundary": case.boundary,
        "sink_surface": case.sink_surface,
        "payload_visibility": case.payload_visibility,
        "expected_leak": case.is_leak,
        "recommended_action": case.recommended_action,
        "observe_only": case.observe_only,
        "profiles": {
            PROFILE_DIRECT: direct,
            PROFILE_RESOLVED: resolved,
            PROFILE_SEMANTIC: semantic,
            PROFILE_LINEAGE: lineage,
        },
    }


def _direct_payload_values(
    case: SinkBenchmarkCase,
    payload: dict[str, Any],
) -> tuple[str, ...]:
    if case.ingestion.expected_adapter == "bash":
        command = payload.get("tool_input", {}).get("command")
        return (command,) if isinstance(command, str) else ()
    if case.ingestion.expected_adapter == "mcp":
        return tuple(_string_leaves(payload.get("tool_input")))
    message = payload.get("last_assistant_message")
    return (message,) if isinstance(message, str) else ()


def _resolved_payload_values(
    case: SinkBenchmarkCase,
    payload: dict[str, Any],
) -> tuple[tuple[str, ...], str | None]:
    if case.ingestion.expected_adapter != "bash":
        return _direct_payload_values(case, payload), None
    command = payload.get("tool_input", {}).get("command")
    if not isinstance(command, str):
        return (), "bash_command_missing"
    projections = extract_bash_http_submissions(command)
    if not projections:
        return (), "bash_http_payload_not_projected"
    if any(projection.extraction == "coarse_fallback" for projection in projections):
        return (), "dynamic_or_file_backed_bash_payload"
    return (
        tuple(
            value
            for projection in projections
            for value in projection.submitted_values
        ),
        None,
    )


def _string_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _string_leaves(item)
    elif isinstance(value, dict):
        for key in sorted(value):
            yield from _string_leaves(value[key])


def _evaluate_values(
    chunks: list[SourceChunk],
    values: tuple[str, ...],
    *,
    case: SinkBenchmarkCase,
    embedding_backend: EmbeddingBackend | None,
) -> dict[str, Any]:
    best: SimilarityDecision | None = None
    for chunk in chunks:
        for value in values:
            normalized = normalize_text(value)
            decision = compare_source_binding_text(
                source_binding_signal=chunk.source_binding_signal,
                left_text=chunk.text,
                left_normalized=chunk.normalized_text,
                left_hash=chunk.text_hash,
                right_text=value,
                right_normalized=normalized,
                right_hash=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                embedding_backend=None,
                minimum_length=4,
            )
            if not decision.matched and embedding_backend is not None:
                semantic_score = embedding_backend.cosine_similarity(
                    chunk.text,
                    value,
                )
                if (
                    isinstance(semantic_score, bool)
                    or not isinstance(semantic_score, (int, float))
                    or not math.isfinite(semantic_score)
                    or not 0.0 <= semantic_score <= 1.0
                ):
                    raise ValueError(
                        "embedding backend score must be finite and between 0 and 1"
                    )
                decision = SimilarityDecision(
                    method="embedding_cosine",
                    score=float(semantic_score),
                    reason="sink benchmark embedding cosine similarity",
                    matched=semantic_score >= 0.80,
                )
            if best is None or decision.score > best.score:
                best = decision
    if best is None:
        best = SimilarityDecision("none", 0.0, "no payload values", False)
    action = _policy_action(case, best.score) if best.matched else "allow"
    return _profile_result(
        status="evaluated",
        detected=best.matched,
        action=action,
        decision=best,
        payload_unit_count=len(values),
    )


def _policy_action(case: SinkBenchmarkCase, score: float) -> str:
    finding = LeakFinding(
        finding_id=f"benchmark:{case.case_id}",
        analysis_run_id="sink-benchmark",
        source_node_kind="source_chunk",
        source_node_id=f"source:{case.case_id}",
        sink_node_id=f"sink:{case.case_id}",
        sink_type=case.sink_surface,
        sink_label="benchmark sink",
        severity=severity_for_score(score),
        path_score=score,
        hop_count=1,
        predecessor_edge_id=None,
        reason="sink benchmark similarity reached sink payload",
    )
    return evaluate_policy([finding])[0].action


def _profile_result(
    *,
    status: str,
    detected: bool | None,
    action: str | None,
    decision: SimilarityDecision | None,
    payload_unit_count: int,
    unsupported_reason: str | None = None,
    method: str | None = None,
    score: float | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "detected": detected,
        "action": action,
        "method": method if method is not None else (decision.method if decision else None),
        "score": (
            round(score, 6)
            if score is not None
            else (round(decision.score, 6) if decision is not None else None)
        ),
        "payload_unit_count": payload_unit_count,
        "unsupported_reason": unsupported_reason,
    }


def _profile_metrics(
    cases: list[dict[str, Any]],
    profile: str,
    *,
    include_observe_only: bool,
) -> dict[str, Any]:
    selected = [
        case for case in cases if include_observe_only or not case["observe_only"]
    ]
    evaluated = [
        case for case in selected if case["profiles"][profile]["status"] == "evaluated"
    ]
    true_positive_ids = [
        case["id"]
        for case in evaluated
        if case["expected_leak"] and case["profiles"][profile]["detected"]
    ]
    false_positive_ids = [
        case["id"]
        for case in evaluated
        if not case["expected_leak"] and case["profiles"][profile]["detected"]
    ]
    false_negative_ids = [
        case["id"]
        for case in evaluated
        if case["expected_leak"] and not case["profiles"][profile]["detected"]
    ]
    true_negative_ids = [
        case["id"]
        for case in evaluated
        if not case["expected_leak"] and not case["profiles"][profile]["detected"]
    ]
    tp = len(true_positive_ids)
    fp = len(false_positive_ids)
    fn = len(false_negative_ids)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    action_mismatch_ids = [
        case["id"]
        for case in evaluated
        if case["profiles"][profile]["action"] != case["recommended_action"]
    ]
    return {
        "coverage": {
            "total": len(selected),
            "evaluated": len(evaluated),
            "unsupported": sum(
                case["profiles"][profile]["status"] == "unsupported"
                for case in selected
            ),
            "unavailable": sum(
                case["profiles"][profile]["status"] == "unavailable"
                for case in selected
            ),
        },
        "detection": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": len(true_negative_ids),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_ids": false_positive_ids,
            "false_negative_ids": false_negative_ids,
        },
        "action_accuracy": _ratio(
            len(evaluated) - len(action_mismatch_ids),
            len(evaluated),
        ),
        "action_mismatch_ids": action_mismatch_ids,
    }


def _profile_delta(
    cases: list[dict[str, Any]],
    baseline: str,
    candidate: str,
) -> dict[str, Any]:
    comparable = [
        case
        for case in cases
        if case["profiles"][baseline]["status"] == "evaluated"
        and case["profiles"][candidate]["status"] == "evaluated"
    ]
    return {
        "comparable_case_count": len(comparable),
        "recovered_positive_ids": [
            case["id"]
            for case in comparable
            if case["expected_leak"]
            and not case["profiles"][baseline]["detected"]
            and case["profiles"][candidate]["detected"]
        ],
        "introduced_false_positive_ids": [
            case["id"]
            for case in comparable
            if not case["expected_leak"]
            and not case["profiles"][baseline]["detected"]
            and case["profiles"][candidate]["detected"]
        ],
    }


def _privacy_exposure_ids(
    report: dict[str, Any],
    cases: tuple[SinkBenchmarkCase, ...],
) -> list[str]:
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    exposed: list[str] = []
    for case in cases:
        sensitive_values = (
            case.ingestion.source.content,
            *case.ingestion.source.protected_values,
            *_direct_payload_values(
                case,
                case.ingestion.events[-1].payload,
            ),
        )
        if any(value and value in serialized for value in sensitive_values):
            exposed.append(case.case_id)
    return exposed


def _ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def _format_ratio(value: float) -> str:
    return f"{value:.3f}"
