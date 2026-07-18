from __future__ import annotations

import json
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from hook_monitor.analysis.leak_detection import LeakFinding, detect_leaks
from hook_monitor.evaluation.source_ingestion_dataset import (
    SourceIngestionDataset,
    SourceIngestionScenario,
    materialize_payload,
)
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.incremental_analysis import (
    RUNTIME_GRAPH_DETECTOR_VERSION,
    RuntimeAnalysisResult,
    update_runtime_analysis,
)
from hook_monitor.runtime.models import (
    AnalysisCursor,
    FlowEdge,
    LineageAssignment,
    NormalizedEvent,
    ProtectedSource,
    ResourceVersion,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.operations import extract_tool_operations
from hook_monitor.runtime.parser import (
    build_artifacts,
    build_fragments,
    json_nesting_exceeds_limit,
    normalize_event,
    parse_hook_payload,
)
from hook_monitor.runtime.pre_tool_policy import (
    evaluate_pre_tool_input_bounds,
    pre_tool_adapter,
)
from hook_monitor.runtime.runner import (
    PRE_TOOL_RAW_JSON_MAX_BYTES,
    PRE_TOOL_RAW_JSON_MAX_DEPTH,
    PRE_TOOL_RAW_JSON_MAX_NUMBER_CHARS,
)
from hook_monitor.runtime.source_config import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    LEGACY_MANIFEST_SCHEMA_VERSION,
    protected_source_selector_payload,
)
from hook_monitor.runtime.storage import EventStore


RUNNER_VERSION = "source-ingestion-evaluation-v2"
DEFAULT_MINIMUM_PATH_SCORE = 0.15
DEFAULT_FINDING_MIN_SCORE = 0.30
_ACTION_PRIORITY = {
    "block": 0,
    "continue_review": 1,
    "warn": 2,
    "allow": 3,
}


@dataclass(frozen=True)
class _ExecutionSnapshot:
    outcome: dict[str, Any]
    mode: str
    source_signatures: tuple[tuple[Any, ...], ...]
    chunk_signatures: tuple[tuple[Any, ...], ...]
    resource_signatures: tuple[tuple[Any, ...], ...]
    sink_signatures: tuple[tuple[Any, ...], ...]
    artifact_edge_signatures: tuple[tuple[Any, ...], ...]
    source_edge_signatures: tuple[tuple[Any, ...], ...]
    assignment_signatures: tuple[tuple[Any, ...], ...]
    finding_signatures: tuple[tuple[Any, ...], ...]
    decision_signatures: tuple[tuple[Any, ...], ...]
    cursor_signature: tuple[Any, ...] | None


def evaluate_source_ingestion(
    dataset: SourceIngestionDataset,
    *,
    split: str | None = "development",
    minimum_path_score: float = DEFAULT_MINIMUM_PATH_SCORE,
    finding_min_score: float = DEFAULT_FINDING_MIN_SCORE,
) -> dict[str, Any]:
    """Evaluate raw Hook ingestion through the production runtime graph entrypoint."""
    if not 0.0 <= minimum_path_score <= 1.0:
        raise ValueError("minimum_path_score must be between 0 and 1")
    if not 0.0 <= finding_min_score <= 1.0:
        raise ValueError("finding_min_score must be between 0 and 1")

    scenarios = dataset.select_scenarios(split)
    cases: list[dict[str, Any]] = []
    parity_cases: list[dict[str, Any]] = []
    for scenario in scenarios:
        full, incremental = _evaluate_scenario(
            scenario,
            minimum_path_score=minimum_path_score,
            finding_min_score=finding_min_score,
        )
        cases.append(
            {
                "id": scenario.scenario_id,
                "split": scenario.split,
                "tags": list(scenario.tags),
                "observe_only": scenario.observe_only,
                "expected_adapter": scenario.expected_adapter,
                "adapter_observed": full.outcome["adapter_observed"],
                "expected_sink_type": scenario.expected_sink_type,
                "target_sink_count": full.outcome["target_sink_count"],
                "expected_reach": scenario.should_reach_sink,
                "actual_reach": full.outcome["reached"],
                "structured_source_reach": full.outcome["structured_source_reach"],
                "expected_action": scenario.expected_action,
                "actual_action": full.outcome["action"],
                "finding_detected": full.outcome["finding_detected"],
                "severity": full.outcome["severity"],
                "path_score": full.outcome["path_score"],
                "hop_count": full.outcome["hop_count"],
                "source_chunk_count": full.outcome["source_chunk_count"],
                "protected_value_count": full.outcome["protected_value_count"],
                "exact_value_chunk_count": full.outcome[
                    "exact_value_chunk_count"
                ],
                "containing_value_chunk_count": full.outcome[
                    "containing_value_chunk_count"
                ],
                "full_mode": full.mode,
                "incremental_mode": incremental.mode,
            }
        )
        parity_cases.append(_compare_executions(scenario, full, incremental))

    metrics = _metrics(cases, parity_cases)
    return {
        "schema_version": 1,
        "runner_version": RUNNER_VERSION,
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "sha256": dataset.digest_sha256,
            "split": split or "all",
            "scenario_count": len(scenarios),
        },
        "configuration": {
            "detector_version": RUNTIME_GRAPH_DETECTOR_VERSION,
            "minimum_path_score": minimum_path_score,
            "finding_min_score": finding_min_score,
            "embedding_backend": None,
            "network_execution": False,
            "primary_source_node_kind": "source_chunk",
        },
        "metrics": metrics,
        "summary": {
            "gate_reachability_f1": metrics["end_to_end"]["gate"][
                "reachability"
            ]["f1"],
            "gate_action_accuracy": metrics["end_to_end"]["gate"][
                "action_accuracy"
            ],
            "adapter_coverage_accuracy": metrics["adapter_extraction"][
                "accuracy"
            ],
            "exact_value_chunk_recall": metrics["chunking"][
                "exact_value_recall"
            ],
            "parity_passed": metrics["full_incremental_parity"]["passed"],
            "observe_only_scenarios": sum(item.observe_only for item in scenarios),
        },
        "cases": {
            "scenarios": cases,
            "parity": parity_cases,
        },
    }


def render_source_ingestion_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    end_to_end = report["metrics"]["end_to_end"]["gate"]
    reach = end_to_end["reachability"]
    chunking = report["metrics"]["chunking"]
    adapters = report["metrics"]["adapter_extraction"]
    parity = report["metrics"]["full_incremental_parity"]
    lines = [
        (
            f"source ingestion dataset={dataset['id']} version={dataset['version']} "
            f"split={dataset['split']} sha256={dataset['sha256'][:12]}"
        ),
        f"scenarios={dataset['scenario_count']}",
        (
            "source-chunk gate "
            f"reachability_f1={_format_ratio(reach['f1'])} "
            f"precision={_format_ratio(reach['precision'])} "
            f"recall={_format_ratio(reach['recall'])} "
            f"action_accuracy={_format_ratio(end_to_end['action_accuracy'])}"
        ),
        (
            "chunking "
            f"exact_value_recall={_format_ratio(chunking['exact_value_recall'])} "
            f"containing_value_recall="
            f"{_format_ratio(chunking['containing_value_recall'])} "
            f"chunks={chunking['source_chunk_count']}"
        ),
        (
            "adapter extraction "
            f"accuracy={_format_ratio(adapters['accuracy'])} "
            f"matched={adapters['matched']}/{adapters['case_count']}"
        ),
        (
            f"full/incremental parity={'PASS' if parity['passed'] else 'FAIL'} "
            f"cases={parity['case_count']} mismatches={len(parity['mismatch_ids'])}"
        ),
    ]
    failures = sorted(
        {
            *reach["false_positive_ids"],
            *reach["false_negative_ids"],
            *end_to_end["action_mismatch_ids"],
        }
    )
    lines.append(f"accuracy mismatches={','.join(failures) if failures else 'none'}")
    if parity["mismatch_ids"]:
        lines.append(f"parity mismatches={','.join(parity['mismatch_ids'])}")
    return "\n".join(lines)


def _evaluate_scenario(
    scenario: SourceIngestionScenario,
    *,
    minimum_path_score: float,
    finding_min_score: float,
) -> tuple[_ExecutionSnapshot, _ExecutionSnapshot]:
    with tempfile.TemporaryDirectory(
        prefix="tooluseproxy-source-ingestion-"
    ) as temporary_directory:
        root = Path(temporary_directory)
        workspace = root / "workspace"
        workspace.mkdir()
        _materialize_source(workspace, scenario)

        full_store = EventStore(root / "full.db")
        full_store.initialize()
        full_events = [
            _record_raw_event(full_store, workspace, raw_event.phase, raw_event.payload)
            for raw_event in scenario.events
        ]
        full_result = update_runtime_analysis(
            full_store,
            current_event_id=full_events[-1].event_id,
            detector_version=RUNTIME_GRAPH_DETECTOR_VERSION,
            minimum_path_score=minimum_path_score,
        )
        full = _snapshot_execution(
            scenario,
            full_store,
            full_events[-1],
            full_result,
            finding_min_score=finding_min_score,
        )

        incremental_store = EventStore(root / "incremental.db")
        incremental_store.initialize()
        incremental_event: NormalizedEvent | None = None
        incremental_result: RuntimeAnalysisResult | None = None
        for raw_event in scenario.events:
            incremental_event = _record_raw_event(
                incremental_store,
                workspace,
                raw_event.phase,
                raw_event.payload,
            )
            incremental_result = update_runtime_analysis(
                incremental_store,
                current_event_id=incremental_event.event_id,
                detector_version=RUNTIME_GRAPH_DETECTOR_VERSION,
                minimum_path_score=minimum_path_score,
            )
        assert incremental_event is not None
        assert incremental_result is not None
        incremental = _snapshot_execution(
            scenario,
            incremental_store,
            incremental_event,
            incremental_result,
            finding_min_score=finding_min_score,
        )
        return full, incremental


def _materialize_source(
    workspace: Path,
    scenario: SourceIngestionScenario,
) -> None:
    source_path = workspace / scenario.source.path
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(scenario.source.content, encoding="utf-8")
    manifest = {
        "schema_version": (
            CURRENT_MANIFEST_SCHEMA_VERSION
            if scenario.source.selector is not None
            else LEGACY_MANIFEST_SCHEMA_VERSION
        ),
        "sources": [
            {
                "id": scenario.source.source_key,
                "path": scenario.source.path,
                "type": scenario.source.source_type,
                "sensitivity": scenario.source.sensitivity,
                "policy_tags": list(scenario.source.policy_tags),
                **(
                    {}
                    if scenario.source.selector is None
                    else {
                        "selector": protected_source_selector_payload(
                            scenario.source.selector
                        )
                    }
                ),
            }
        ]
    }
    (workspace / "protected_sources.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def _record_raw_event(
    store: EventStore,
    workspace: Path,
    phase: str,
    fixture_payload: dict[str, Any],
) -> NormalizedEvent:
    materialized = materialize_payload(fixture_payload, workspace)
    raw_bytes = json.dumps(
        materialized,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    adapter = pre_tool_adapter(materialized.get("tool_name"))
    bounded_mcp_input = phase == "pre_tool_use" and adapter == "mcp"
    if bounded_mcp_input and len(raw_bytes) > PRE_TOOL_RAW_JSON_MAX_BYTES:
        raise ValueError("fixture exceeds the production raw Hook byte limit")
    if bounded_mcp_input and json_nesting_exceeds_limit(
        raw_bytes,
        PRE_TOOL_RAW_JSON_MAX_DEPTH,
    ):
        raise ValueError("fixture exceeds the production raw Hook nesting limit")
    payload = parse_hook_payload(
        raw_bytes,
        max_number_chars=(
            PRE_TOOL_RAW_JSON_MAX_NUMBER_CHARS if bounded_mcp_input else None
        ),
    )
    event = normalize_event(
        phase,
        payload,
        workspace_root=str(workspace),
        workspace_discovered_by="registered_root",
    )
    if phase == "pre_tool_use" and adapter is not None:
        guard = evaluate_pre_tool_input_bounds(
            event,
            enabled_adapters=frozenset({"bash", "mcp"}),
        )
        if guard.disposition != "continue":
            raise ValueError(
                "fixture would not reach production Hook ingestion after input bounds"
            )
    artifacts = build_artifacts(event)
    fragments = build_fragments(artifacts)
    extraction = extract_tool_operations(event, artifacts, fragments)
    fragments.extend(extraction.fragments)
    store.record(
        event,
        artifacts,
        fragments,
        list(extraction.operations),
    )
    return event


def _snapshot_execution(
    scenario: SourceIngestionScenario,
    store: EventStore,
    target_event: NormalizedEvent,
    result: RuntimeAnalysisResult,
    *,
    finding_min_score: float,
) -> _ExecutionSnapshot:
    scope = store.get_runtime_analysis_scope(target_event.event_id)
    sources = store.list_protected_sources_for_workspace(scope.workspace_id)
    cursor = store.get_analysis_cursor(
        scope.session_id,
        workspace_id=scope.workspace_id,
    )
    chunks = store.list_source_chunks_for_workspace(scope.workspace_id)
    resources = store.list_resource_versions_for_session(
        scope.session_id,
        workspace_id=scope.workspace_id,
    )
    artifact_edges = store.list_information_flow_edges_for_session(
        scope.session_id,
        workspace_id=scope.workspace_id,
    )
    source_edges = store.list_runtime_source_binding_edges(
        scope.session_id,
        workspace_id=scope.workspace_id,
    )
    sinks = store.list_sink_candidates_for_session(
        scope.session_id,
        workspace_id=scope.workspace_id,
    )
    target_sinks = [
        sink
        for sink in sinks
        if sink.sink_type == scenario.expected_sink_type
        and sink.workspace_id == scope.workspace_id
        and sink.session_id == scope.session_id
        and sink.sequence_no == scope.sequence_no
        and sink.metadata.get("event_id") == target_event.event_id
        and sink.metadata.get("adapter") == scenario.expected_adapter
        and (
            target_event.tool_use_id is None
            or sink.tool_use_id == target_event.tool_use_id
        )
    ]
    target_sink_ids = {sink.node_id for sink in target_sinks}
    source_chunk_assignments = [
        assignment
        for assignment in result.assignments
        if assignment.source_node_kind == "source_chunk"
        and assignment.node_kind == "sink_candidate"
        and assignment.node_id in target_sink_ids
    ]
    structured_assignments = [
        assignment
        for assignment in result.assignments
        if assignment.source_node_kind == "protected_source"
        and assignment.node_kind == "sink_candidate"
        and assignment.node_id in target_sink_ids
    ]
    best_assignment = max(
        source_chunk_assignments,
        key=lambda item: item.best_path_score,
        default=None,
    )
    findings = detect_leaks(
        analysis_run=result.analysis_run,
        assignments=list(result.assignments),
        sink_candidates=target_sinks,
        min_score=finding_min_score,
        sink_types={scenario.expected_sink_type},
        included_sink_types=(
            {"final_answer"}
            if scenario.expected_sink_type == "final_answer"
            else None
        ),
        source_filter={
            ("source_chunk", chunk.chunk_id)
            for chunk in chunks
        },
    )
    decisions = evaluate_policy(findings)
    strongest = min(
        decisions,
        key=lambda item: _ACTION_PRIORITY.get(item.action, 99),
        default=None,
    )
    exact_value_count = sum(
        any(chunk.text == value for chunk in chunks)
        for value in scenario.source.protected_values
    )
    containing_value_count = sum(
        any(value in chunk.text for chunk in chunks)
        for value in scenario.source.protected_values
    )
    outcome = {
        "adapter_observed": bool(target_sinks),
        "target_sink_count": len(target_sinks),
        "reached": best_assignment is not None,
        "structured_source_reach": bool(structured_assignments),
        "finding_detected": bool(findings),
        "action": strongest.action if strongest is not None else "allow",
        "severity": strongest.severity if strongest is not None else None,
        "path_score": (
            round(best_assignment.best_path_score, 6)
            if best_assignment is not None
            else None
        ),
        "hop_count": (
            best_assignment.hop_count if best_assignment is not None else None
        ),
        "source_chunk_count": len(chunks),
        "protected_value_count": len(scenario.source.protected_values),
        "exact_value_chunk_count": exact_value_count,
        "containing_value_chunk_count": containing_value_count,
    }
    return _ExecutionSnapshot(
        outcome=outcome,
        mode=result.mode,
        source_signatures=_source_signatures(sources),
        chunk_signatures=_chunk_signatures(chunks),
        resource_signatures=_resource_signatures(resources),
        sink_signatures=_sink_signatures(sinks),
        artifact_edge_signatures=_edge_signatures(artifact_edges),
        source_edge_signatures=_edge_signatures(source_edges),
        assignment_signatures=_assignment_signatures(result.assignments),
        finding_signatures=_finding_signatures(findings),
        decision_signatures=_decision_signatures(decisions),
        cursor_signature=_cursor_signature(cursor),
    )


def _compare_executions(
    scenario: SourceIngestionScenario,
    full: _ExecutionSnapshot,
    incremental: _ExecutionSnapshot,
) -> dict[str, Any]:
    comparisons = {
        "sources_equal": full.source_signatures == incremental.source_signatures,
        "chunks_equal": full.chunk_signatures == incremental.chunk_signatures,
        "resources_equal": (
            full.resource_signatures == incremental.resource_signatures
        ),
        "sinks_equal": full.sink_signatures == incremental.sink_signatures,
        "artifact_edges_equal": (
            full.artifact_edge_signatures == incremental.artifact_edge_signatures
        ),
        "source_edges_equal": (
            full.source_edge_signatures == incremental.source_edge_signatures
        ),
        "assignments_equal": (
            full.assignment_signatures == incremental.assignment_signatures
        ),
        "findings_equal": (
            full.finding_signatures == incremental.finding_signatures
        ),
        "decisions_equal": (
            full.decision_signatures == incremental.decision_signatures
        ),
        "cursor_equal": full.cursor_signature == incremental.cursor_signature,
        "outcome_equal": full.outcome == incremental.outcome,
        "full_mode_valid": full.mode == "session-full",
        "incremental_mode_valid": incremental.mode == "session-incremental",
    }
    return {
        "id": scenario.scenario_id,
        **comparisons,
        "passed": all(comparisons.values()),
    }


def _source_signatures(
    sources: Sequence[ProtectedSource],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                source.source_id,
                source.path,
                source.source_type,
                source.sensitivity,
                source.policy_tags,
                source.workspace_id,
                source.source_key,
                (
                    None
                    if source.selector is None
                    else (source.selector.kind, source.selector.values)
                ),
            )
            for source in sources
        )
    )


def _cursor_signature(cursor: AnalysisCursor | None) -> tuple[Any, ...] | None:
    if cursor is None:
        return None
    return (
        cursor.workspace_id,
        cursor.session_id,
        cursor.detector_version,
        cursor.source_digest,
        cursor.last_sequence_no,
        cursor.status,
    )


def _chunk_signatures(
    chunks: Sequence[SourceChunk],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                chunk.chunk_id,
                chunk.source_id,
                chunk.ordinal,
                chunk.text_hash,
                chunk.normalized_text,
                chunk.shingle_fingerprint,
                chunk.token_count,
                chunk.workspace_id,
            )
            for chunk in chunks
        )
    )


def _resource_signatures(
    resources: Sequence[ResourceVersion],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                resource.node_id,
                resource.path,
                resource.content_hash,
                resource.sequence_no,
                resource.session_id,
                resource.origin_tool_use_id,
                resource.operation_id,
                resource.operation_index,
                resource.snapshot_id,
                resource.resource_state,
                resource.workspace_id,
            )
            for resource in resources
        )
    )


def _sink_signatures(
    sinks: Sequence[SinkCandidate],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                sink.node_id,
                sink.sink_type,
                sink.label,
                sink.tool_name,
                sink.tool_use_id,
                sink.session_id,
                sink.sequence_no,
                json.dumps(sink.metadata, ensure_ascii=False, sort_keys=True),
                sink.workspace_id,
            )
            for sink in sinks
        )
    )


def _edge_signatures(
    edges: Sequence[FlowEdge],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                edge.edge_id,
                edge.src_node_kind,
                edge.src_node_id,
                edge.dst_node_kind,
                edge.dst_node_id,
                edge.relation,
                edge.evidence_level,
                edge.method,
                round(edge.score, 12),
                edge.reason,
            )
            for edge in edges
        )
    )


def _assignment_signatures(
    assignments: Sequence[LineageAssignment],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                assignment.source_node_kind,
                assignment.source_node_id,
                assignment.node_kind,
                assignment.node_id,
                round(assignment.best_path_score, 12),
                assignment.predecessor_edge_id,
                assignment.hop_count,
            )
            for assignment in assignments
        )
    )


def _finding_signatures(
    findings: Sequence[LeakFinding],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                finding.source_node_kind,
                finding.source_node_id,
                finding.sink_node_id,
                finding.sink_type,
                finding.sink_label,
                finding.severity,
                round(finding.path_score, 12),
                finding.hop_count,
                finding.predecessor_edge_id,
                finding.reason,
            )
            for finding in findings
        )
    )


def _decision_signatures(
    decisions: Sequence[PolicyDecision],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                decision.action,
                decision.severity,
                decision.sink_type,
                decision.source_node_kind,
                decision.source_node_id,
                decision.sink_node_id,
                round(decision.path_score, 12),
                decision.hook_event,
                decision.reason,
            )
            for decision in decisions
        )
    )


def _metrics(
    cases: list[dict[str, Any]],
    parity_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    gate_cases = [item for item in cases if not item["observe_only"]]
    adapters = Counter(
        item["expected_adapter"]
        for item in cases
        if item["adapter_observed"]
    )
    protected_value_count = sum(item["protected_value_count"] for item in cases)
    exact_value_count = sum(item["exact_value_chunk_count"] for item in cases)
    containing_value_count = sum(
        item["containing_value_chunk_count"] for item in cases
    )
    mismatches = sorted(item["id"] for item in parity_cases if not item["passed"])
    return {
        "adapter_extraction": {
            "case_count": len(cases),
            "matched": sum(item["adapter_observed"] for item in cases),
            "accuracy": _safe_ratio(
                sum(item["adapter_observed"] for item in cases),
                len(cases),
            ),
            "matched_by_adapter": dict(sorted(adapters.items())),
            "missing_ids": sorted(
                item["id"] for item in cases if not item["adapter_observed"]
            ),
        },
        "chunking": {
            "protected_value_count": protected_value_count,
            "exact_value_chunk_count": exact_value_count,
            "containing_value_chunk_count": containing_value_count,
            "source_chunk_count": sum(item["source_chunk_count"] for item in cases),
            "exact_value_recall": _safe_ratio(
                exact_value_count,
                protected_value_count,
            ),
            "containing_value_recall": _safe_ratio(
                containing_value_count,
                protected_value_count,
            ),
        },
        "end_to_end": {
            "all": _scenario_summary(cases),
            "gate": _scenario_summary(gate_cases),
            "by_adapter": {
                adapter: _scenario_summary(
                    [item for item in cases if item["expected_adapter"] == adapter]
                )
                for adapter in sorted({item["expected_adapter"] for item in cases})
            },
        },
        "full_incremental_parity": {
            "implementation": "production_runtime_analysis_entrypoint_v1",
            "scope": (
                "Compares persisted sources, chunks, resources, sinks, artifact and "
                "source edges, lineage, findings, decisions, analysis cursor, and "
                "target outcome."
            ),
            "case_count": len(parity_cases),
            "passed": not mismatches,
            "mismatch_ids": mismatches,
        },
    }


def _scenario_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    reach_cases = [
        {
            "id": item["id"],
            "expected": item["expected_reach"],
            "actual": item["actual_reach"],
        }
        for item in cases
    ]
    action_matrix: dict[str, Counter[str]] = defaultdict(Counter)
    for item in cases:
        action_matrix[item["expected_action"]][item["actual_action"]] += 1
    action_mismatches = sorted(
        item["id"]
        for item in cases
        if item["expected_action"] != item["actual_action"]
    )
    return {
        "case_count": len(cases),
        "reachability": _binary_summary(reach_cases),
        "action_accuracy": _safe_ratio(
            len(cases) - len(action_mismatches),
            len(cases),
        ),
        "action_confusion": {
            expected: dict(sorted(actual.items()))
            for expected, actual in sorted(action_matrix.items())
        },
        "action_mismatch_ids": action_mismatches,
        "false_blocks": sorted(
            item["id"]
            for item in cases
            if item["expected_action"] == "allow" and item["actual_action"] == "block"
        ),
        "unexpected_warnings": sorted(
            item["id"]
            for item in cases
            if item["expected_action"] == "allow" and item["actual_action"] == "warn"
        ),
        "missed_blocks": sorted(
            item["id"]
            for item in cases
            if item["expected_action"] == "block" and item["actual_action"] != "block"
        ),
        "missed_reviews": sorted(
            item["id"]
            for item in cases
            if item["expected_action"] == "continue_review"
            and item["actual_action"] != "continue_review"
        ),
    }


def _binary_summary(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(item["expected"] and item["actual"] for item in cases)
    fp = sum(not item["expected"] and item["actual"] for item in cases)
    tn = sum(not item["expected"] and not item["actual"] for item in cases)
    fn = sum(item["expected"] and not item["actual"] for item in cases)
    precision = _optional_ratio(tp, tp + fp)
    recall = _optional_ratio(tp, tp + fn)
    f1 = (
        _safe_ratio(2 * precision * recall, precision + recall)
        if precision is not None and recall is not None
        else None
    )
    return {
        "case_count": len(cases),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "accuracy": _safe_ratio(tp + tn, len(cases)),
        "f1": f1,
        "false_positive_ids": sorted(
            item["id"]
            for item in cases
            if not item["expected"] and item["actual"]
        ),
        "false_negative_ids": sorted(
            item["id"]
            for item in cases
            if item["expected"] and not item["actual"]
        ),
    }


def _safe_ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _optional_ratio(numerator: float, denominator: float) -> float | None:
    return _safe_ratio(numerator, denominator) if denominator else None


def _format_ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"
