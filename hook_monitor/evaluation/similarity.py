from __future__ import annotations

import hashlib
import json
import math
import re
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from hook_monitor.analysis.adapters.common import make_submitted_to_edge
from hook_monitor.analysis.graph import (
    MAX_LEXICAL_CANDIDATES,
    MAX_SOURCE_CANDIDATES,
    build_artifact_flow_edges,
    build_source_binding_edges,
)
from hook_monitor.analysis.leak_detection import LeakFinding, detect_leaks
from hook_monitor.analysis.lineage import propagate_lineage
from hook_monitor.analysis.lineage import propagate_lineage_incremental
from hook_monitor.analysis.similarity import (
    SIMILARITY_PROFILE_VERSION,
    SIMILARITY_SHINGLE_SIZE,
    SIMILARITY_SHINGLE_THRESHOLD,
    SimilarityCandidateStats,
    SimilarityDecision,
    compare_text,
    make_shingles,
    prepare_similarity_text,
    rank_similarity_candidate_ids,
)
from hook_monitor.evaluation.dataset import (
    LineageScenario,
    PairExample,
    RetrievalPool,
    SimilarityDataset,
    SUPPORTED_PAIR_SCOPES,
)
from hook_monitor.policy.engine import evaluate_policy
from hook_monitor.policy.models import PolicyDecision
from hook_monitor.runtime.models import (
    AnalysisRun,
    ArtifactContext,
    ArtifactFragment,
    ArtifactRecord,
    FlowEdge,
    LineageAssignment,
    NormalizedEvent,
    SinkCandidate,
    SourceChunk,
)
from hook_monitor.runtime.incremental_analysis import _build_delta_similarity_edges
from hook_monitor.runtime.ids import make_event_id
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace


REPORT_SCHEMA_VERSION = 2
RUNNER_VERSION = "similarity-evaluation-v2"
V21_REPORT_SCHEMA_VERSION = 3
V21_RUNNER_VERSION = "similarity-evaluation-v2.1"
DEFAULT_MINIMUM_PATH_SCORE = 0.15
DEFAULT_FINDING_MIN_SCORE = 0.30
_ACTION_PRIORITY = {
    "block": 0,
    "continue_review": 1,
    "warn": 2,
    "allow": 3,
}
_PRIVACY_CANARY_PATTERN = re.compile(r"\bC\.[A-Z0-9][A-Z0-9._-]{7,}\b")
_MIN_PRIVACY_BODY_PROBE_LENGTH = 16


@dataclass(frozen=True)
class RetrievalCandidate:
    candidate_id: str
    text: str
    sequence_no: int


@dataclass(frozen=True)
class _ScenarioMaterial:
    source: SourceChunk
    contexts: tuple[ArtifactContext, ...]
    sink: SinkCandidate
    sink_edge: FlowEdge


@dataclass(frozen=True)
class _ScenarioExecution:
    outcome: dict[str, Any]
    artifact_edges: tuple[FlowEdge, ...]
    source_edges: tuple[FlowEdge, ...]
    assignment_signatures: tuple[tuple[Any, ...], ...]
    finding_signatures: tuple[tuple[Any, ...], ...]
    decision_signatures: tuple[tuple[Any, ...], ...]


@dataclass(frozen=True)
class _ScenarioAssessment:
    outcome: dict[str, Any]
    assignment_signatures: tuple[tuple[Any, ...], ...]
    finding_signatures: tuple[tuple[Any, ...], ...]
    decision_signatures: tuple[tuple[Any, ...], ...]


def evaluate_similarity(
    dataset: SimilarityDataset,
    *,
    split: str | None = "development",
    benchmark_repeats: int = 20,
    minimum_path_score: float = DEFAULT_MINIMUM_PATH_SCORE,
    finding_min_score: float = DEFAULT_FINDING_MIN_SCORE,
) -> dict[str, Any]:
    if type(benchmark_repeats) is not int or not 1 <= benchmark_repeats <= 1_000:
        raise ValueError("benchmark_repeats must be an integer between 1 and 1000")
    if not 0.0 <= minimum_path_score <= 1.0:
        raise ValueError("minimum_path_score must be between 0 and 1")
    if not 0.0 <= finding_min_score <= 1.0:
        raise ValueError("finding_min_score must be between 0 and 1")

    pairs = dataset.select_pairs(split)
    scenarios = dataset.select_scenarios(split)
    pair_cases = [_evaluate_pair(pair) for pair in pairs]
    explicit_retrieval_pools = dataset.select_retrieval_pools(split)
    retrieval_cases = (
        _evaluate_retrieval_pools(explicit_retrieval_pools)
        if explicit_retrieval_pools
        else _evaluate_retrieval(pairs)
    )

    scenario_results: list[dict[str, Any]] = []
    parity_cases: list[dict[str, Any]] = []
    for scenario in scenarios:
        material = _make_scenario_material(scenario)
        full = _run_full_scenario(
            scenario,
            material,
            minimum_path_score=minimum_path_score,
            finding_min_score=finding_min_score,
        )
        incremental = _run_incremental_scenario(
            scenario,
            minimum_path_score=minimum_path_score,
            finding_min_score=finding_min_score,
        )
        scenario_results.append(
            {
                "id": scenario.scenario_id,
                "split": scenario.split,
                "tags": list(scenario.tags),
                "family": scenario.family,
                "counterfactual_group": scenario.counterfactual_group,
                "source_binding_signal": scenario.source_binding_signal,
                "observe_only": scenario.observe_only,
                "expected_reach": scenario.should_reach_sink,
                "actual_reach": full.outcome["reached"],
                "expected_action": scenario.expected_action,
                "actual_action": full.outcome["action"],
                "finding_detected": full.outcome["finding_detected"],
                "severity": full.outcome["severity"],
                "path_score": full.outcome["path_score"],
                "hop_count": full.outcome["hop_count"],
            }
        )
        parity_cases.append(_compare_scenario_executions(scenario, full, incremental))

    latency = _benchmark(
        pairs,
        scenarios,
        retrieval_pools=explicit_retrieval_pools,
        benchmark_repeats=benchmark_repeats,
        minimum_path_score=minimum_path_score,
        finding_min_score=finding_min_score,
    )
    split_name = split or "all"
    report_schema_version = (
        V21_REPORT_SCHEMA_VERSION if dataset.schema_version >= 3 else REPORT_SCHEMA_VERSION
    )
    runner_version = V21_RUNNER_VERSION if dataset.schema_version >= 3 else RUNNER_VERSION
    pair_metrics = _pair_metrics(pair_cases)
    retrieval_metrics = _retrieval_metrics(
        retrieval_cases,
        dataset_schema_version=dataset.schema_version,
    )
    end_to_end_metrics = _end_to_end_metrics(scenario_results)
    parity_metrics = _parity_metrics(parity_cases)
    report = {
        "schema_version": report_schema_version,
        "runner_version": runner_version,
        "dataset": {
            "id": dataset.dataset_id,
            "schema_version": dataset.schema_version,
            "version": dataset.dataset_version,
            "sha256": dataset.digest_sha256,
            "digest_matches_pinned": (
                dataset.digest_sha256 == dataset.pinned_digest_sha256
            ),
            "split": split_name,
            "pair_count": len(pairs),
            "scenario_count": len(scenarios),
            "retrieval_pool_count": len(explicit_retrieval_pools),
            "split_contract": dataset.split_contract,
            "stress_contract": dataset.stress_contract,
        },
        "configuration": {
            "artifact_candidate_limit": MAX_LEXICAL_CANDIDATES,
            "source_candidate_limit": MAX_SOURCE_CANDIDATES,
            "artifact_minimum_length": 8,
            "source_minimum_length": 4,
            "similarity_profile": SIMILARITY_PROFILE_VERSION,
            "shingle_size": SIMILARITY_SHINGLE_SIZE,
            "shingle_jaccard_threshold": SIMILARITY_SHINGLE_THRESHOLD,
            "embedding_backend": None,
            "minimum_path_score": minimum_path_score,
            "finding_min_score": finding_min_score,
            "critical_score": 0.90,
            "high_score": 0.60,
            "benchmark_repeats": benchmark_repeats,
        },
        "metrics": {
            "candidate_retrieval": retrieval_metrics,
            "pair_classification": pair_metrics,
            "end_to_end": end_to_end_metrics,
            "full_incremental_parity": parity_metrics,
            "latency_ms": {
                "scope": (
                    "Offline evaluator latency on the current host. Retrieval uses "
                    "the Python simulation; e2e_incremental includes temporary "
                    "SQLite initialization and production incremental graph functions."
                ),
                **latency,
            },
        },
        "summary": {
            "gate_pair_f1": pair_metrics["gate"]["f1"],
            "gate_reachability_f1": end_to_end_metrics["gate"]["reachability"]["f1"],
            "gate_action_accuracy": end_to_end_metrics["gate"]["action_accuracy"],
            "parity_passed": parity_metrics["passed"],
            "observe_only_pairs": sum(item.observe_only for item in pairs),
            "observe_only_scenarios": sum(item.observe_only for item in scenarios),
        },
        "cases": {
            "pairs": pair_cases,
            "retrieval": retrieval_cases,
            "scenarios": scenario_results,
            "parity": parity_cases,
        },
    }
    _finish_evaluation_contract(
        report,
        dataset,
        split=split,
        pair_cases=pair_cases,
        retrieval_cases=retrieval_cases,
        scenario_cases=scenario_results,
        parity_metrics=parity_metrics,
    )
    return report


def render_similarity_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    retrieval = report["metrics"]["candidate_retrieval"]
    pairs = report["metrics"]["pair_classification"]
    end_to_end = report["metrics"]["end_to_end"]
    parity = report["metrics"]["full_incremental_parity"]
    latency = report["metrics"]["latency_ms"]
    lines = [
        (
            f"similarity evaluation runner={report['runner_version']} "
            f"dataset={dataset['id']} version={dataset['version']} "
            f"split={dataset['split']} sha256={dataset['sha256'][:12]}"
        ),
        (
            f"pairs={dataset['pair_count']} scenarios={dataset['scenario_count']} "
            f"retrieval_pools={dataset['retrieval_pool_count']}"
        ),
    ]
    for scope in ("artifact_flow", "source_binding"):
        item = retrieval[scope]["gate"]
        pool_status = (
            "pool_exceeds_cap"
            if retrieval[scope]["pool_exceeds_limit"]
            else "cap_not_exercised"
        )
        lines.append(
            f"candidate {scope} recall@{retrieval[scope]['limit']}="
            f"{_format_ratio(item['recall'])} ({item['retrieved']}/{item['positive_cases']}) "
            f"pool={retrieval[scope]['pool_size']} {pool_status} "
            f"saturation_rate={_format_ratio(retrieval[scope]['saturation_rate'])} "
            f"saturated_recall={_format_ratio(retrieval[scope]['gate_saturated']['recall'])} "
            f"candidate_sets_sha256={item['candidate_sets_sha256'][:12]}"
        )
    gate_pairs = pairs["gate"]
    lines.append(
        "pair gate "
        f"precision={_format_ratio(gate_pairs['precision'])} "
        f"recall={_format_ratio(gate_pairs['recall'])} "
        f"f1={_format_ratio(gate_pairs['f1'])} "
        f"tp={gate_pairs['tp']} fp={gate_pairs['fp']} "
        f"tn={gate_pairs['tn']} fn={gate_pairs['fn']}"
    )
    reach = end_to_end["gate"]["reachability"]
    lines.append(
        "e2e gate "
        f"reachability_f1={_format_ratio(reach['f1'])} "
        f"action_accuracy={_format_ratio(end_to_end['gate']['action_accuracy'])} "
        f"false_blocks={len(end_to_end['gate']['false_blocks'])} "
        f"unexpected_warnings={len(end_to_end['gate']['unexpected_warnings'])} "
        f"missed_blocks={len(end_to_end['gate']['missed_blocks'])}"
    )
    lines.append(
        f"full/incremental parity={'PASS' if parity['passed'] else 'FAIL'} "
        f"cases={parity['case_count']} mismatches={len(parity['mismatch_ids'])}"
    )
    summary = report["summary"]
    lines.append(
        f"contract check={'PASS' if summary['check_passed'] else 'FAIL'} "
        f"digest={'PASS' if dataset['digest_matches_pinned'] else 'FAIL'} "
        f"baseline={'PASS' if summary['baseline_reproduced'] else 'FAIL'} "
        f"privacy={'PASS' if summary['privacy_passed'] else 'FAIL'}"
    )
    quality = report["quality"]
    if quality["available"]:
        failed_checks = [
            name for name, passed in quality["checks"].items() if not passed
        ]
        lines.append(
            f"quality require-go={'PASS' if quality['passed'] else 'FAIL'} "
            f"failed={','.join(failed_checks) if failed_checks else 'none'}"
        )
    lines.append(
        "latency p95 ms "
        f"pair={latency['pair']['p95']:.3f} "
        f"artifact_retrieval={latency['artifact_retrieval']['p95']:.3f} "
        f"source_retrieval={latency['source_retrieval']['p95']:.3f} "
        f"e2e_full={latency['e2e_full']['p95']:.3f} "
        f"e2e_incremental={latency['e2e_incremental']['p95']:.3f}"
    )
    if gate_pairs["false_positive_ids"]:
        lines.append(f"pair false positives: {', '.join(gate_pairs['false_positive_ids'])}")
    if gate_pairs["false_negative_ids"]:
        lines.append(f"pair false negatives: {', '.join(gate_pairs['false_negative_ids'])}")
    all_pairs = pairs["all"]
    if all_pairs != gate_pairs:
        lines.append(
            "pair all including observe-only "
            f"precision={_format_ratio(all_pairs['precision'])} "
            f"recall={_format_ratio(all_pairs['recall'])} "
            f"f1={_format_ratio(all_pairs['f1'])} "
            f"fn={all_pairs['fn']}"
        )
    all_reach = end_to_end["all"]["reachability"]
    if end_to_end["all"]["case_count"] != end_to_end["gate"]["case_count"]:
        lines.append(
            "e2e all including observe-only "
            f"reachability_f1={_format_ratio(all_reach['f1'])} "
            f"action_accuracy={_format_ratio(end_to_end['all']['action_accuracy'])}"
        )
    return "\n".join(lines)


def simulate_candidate_retrieval(
    *,
    scope: str,
    query_text: str,
    candidates: Sequence[RetrievalCandidate],
) -> tuple[str, ...]:
    """Reproduce production exact-key and candidate-feature eligibility."""

    if scope not in SUPPORTED_PAIR_SCOPES:
        raise ValueError(f"unsupported retrieval scope: {scope}")
    candidate_ids = [item.candidate_id for item in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("retrieval candidate ids must be unique")

    query_normalized = normalize_text(query_text)
    prepared_query = prepare_similarity_text(
        query_text,
        normalized_text=query_normalized,
    )
    normalized_candidates = {
        item.candidate_id: normalize_text(item.text) for item in candidates
    }
    prepared_candidates = {
        item.candidate_id: prepare_similarity_text(
            item.text,
            normalized_text=normalized_candidates[item.candidate_id],
        )
        for item in candidates
    }
    exact = [
        item
        for item in candidates
        if prepared_candidates[item.candidate_id].primary_exact_key
        == prepared_query.primary_exact_key
    ]
    if scope == "artifact_flow" and exact:
        latest = max(exact, key=lambda item: (item.sequence_no, item.candidate_id))
        return (latest.candidate_id,)

    exact_ids = sorted(item.candidate_id for item in exact)
    exact_id_set = set(exact_ids)
    limit = (
        MAX_LEXICAL_CANDIDATES
        if scope == "artifact_flow"
        else MAX_SOURCE_CANDIDATES
    )
    candidate_stats: list[SimilarityCandidateStats] = []
    for item in candidates:
        if scope == "source_binding" and item.candidate_id in exact_id_set:
            continue
        prepared_candidate = prepared_candidates[item.candidate_id]
        overlap = len(
            prepared_query.candidate_features
            & prepared_candidate.candidate_features
        )
        if overlap:
            candidate_stats.append(
                SimilarityCandidateStats(
                    candidate_id=item.candidate_id,
                    overlap_count=overlap,
                    candidate_feature_count=len(
                        prepared_candidate.candidate_features
                    ),
                    candidate_normalized_length=len(
                        normalized_candidates[item.candidate_id]
                    ),
                )
            )
    lexical_ids = rank_similarity_candidate_ids(
        query_feature_count=len(prepared_query.candidate_features),
        query_normalized_length=len(query_normalized),
        minimum_length=4 if scope == "source_binding" else 8,
        candidates=candidate_stats,
        limit=limit,
    )
    if scope == "artifact_flow":
        return tuple(lexical_ids)
    return tuple(dict.fromkeys((*exact_ids, *lexical_ids)))


def nearest_rank_percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 < percentile <= 1.0:
        raise ValueError("percentile must be greater than 0 and at most 1")
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _evaluate_pair(pair: PairExample) -> dict[str, Any]:
    decision = _compare_pair(pair)
    return {
        "id": pair.example_id,
        "split": pair.split,
        "scope": pair.scope,
        "tags": list(pair.tags),
        "family": pair.family,
        "counterfactual_group": pair.counterfactual_group,
        "source_binding_signal": pair.source_binding_signal,
        "observe_only": pair.observe_only,
        "expected": pair.should_link,
        "actual": decision.matched,
        "method": decision.method,
        "score": round(decision.score, 6),
    }


def _compare_pair(pair: PairExample) -> SimilarityDecision:
    return compare_text(
        left_text=pair.left_text,
        left_normalized=normalize_text(pair.left_text),
        left_hash=_text_hash(pair.left_text),
        right_text=pair.right_text,
        right_normalized=normalize_text(pair.right_text),
        right_hash=_text_hash(pair.right_text),
        minimum_length=pair.minimum_length,
    )


def _evaluate_retrieval(pairs: Sequence[PairExample]) -> list[dict[str, Any]]:
    by_scope: dict[str, list[PairExample]] = defaultdict(list)
    for pair in pairs:
        by_scope[pair.scope].append(pair)

    results: list[dict[str, Any]] = []
    for scope in sorted(by_scope):
        scope_pairs = by_scope[scope]
        candidates = [
            RetrievalCandidate(
                candidate_id=pair.example_id,
                text=(
                    pair.left_text
                    if scope == "artifact_flow"
                    else pair.right_text
                ),
                sequence_no=index,
            )
            for index, pair in enumerate(scope_pairs, start=1)
        ]
        for pair in scope_pairs:
            retrieved = simulate_candidate_retrieval(
                scope=scope,
                query_text=(
                    pair.right_text
                    if scope == "artifact_flow"
                    else pair.left_text
                ),
                candidates=candidates,
            )
            results.append(
                {
                    "id": pair.example_id,
                    "split": pair.split,
                    "scope": scope,
                    "family": pair.family,
                    "counterfactual_group": pair.counterfactual_group,
                    "observe_only": pair.observe_only,
                    "relevant": pair.should_link,
                    "retrieved_relevant": pair.example_id in retrieved,
                    "candidate_count": len(retrieved),
                    "candidate_set_sha256": _candidate_set_digest(retrieved),
                    "pool_size": len(candidates),
                    "cap_saturated": len(candidates)
                    > (
                        MAX_LEXICAL_CANDIDATES
                        if scope == "artifact_flow"
                        else MAX_SOURCE_CANDIDATES
                    ),
                }
            )
    return results


def _evaluate_retrieval_pools(
    pools: Sequence[RetrievalPool],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for pool in pools:
        candidates = tuple(
            RetrievalCandidate(
                candidate_id=item.candidate_id,
                text=item.text,
                sequence_no=item.sequence_no,
            )
            for item in pool.candidates
        )
        retrieved = _simulate_production_candidate_retrieval(
            scope=pool.scope,
            query_text=pool.query_text,
            candidates=candidates,
        )
        limit = (
            MAX_LEXICAL_CANDIDATES
            if pool.scope == "artifact_flow"
            else MAX_SOURCE_CANDIDATES
        )
        results.append(
            {
                "id": pool.pool_id,
                "split": pool.split,
                "scope": pool.scope,
                "family": pool.family,
                "counterfactual_group": pool.counterfactual_group,
                "source_binding_signal": pool.source_binding_signal,
                "observe_only": pool.observe_only,
                "relevant": True,
                "retrieved_relevant": pool.relevant_candidate_id in retrieved,
                "candidate_count": len(retrieved),
                "candidate_set_sha256": _candidate_set_digest(retrieved),
                "pool_size": len(candidates),
                "cap_saturated": len(candidates) > limit,
            }
        )
    return results


def _simulate_production_candidate_retrieval(
    *,
    scope: str,
    query_text: str,
    candidates: Sequence[RetrievalCandidate],
) -> tuple[str, ...]:
    return simulate_candidate_retrieval(
        scope=scope,
        query_text=query_text,
        candidates=candidates,
    )


def _candidate_set_digest(candidate_ids: Sequence[str]) -> str:
    """Hash public candidate IDs without exposing fixture or candidate text."""
    digest = hashlib.sha256(b"tooluseproxy-similarity-candidate-set-v1\0")
    digest.update(
        json.dumps(
            sorted(candidate_ids),
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return digest.hexdigest()


def _make_scenario_material(
    scenario: LineageScenario,
    *,
    workspace_id: str = "similarity-evaluation-workspace",
    workspace_root: str = "/synthetic/workspace",
) -> _ScenarioMaterial:
    session_id = f"similarity-evaluation:{scenario.scenario_id}"
    source_normalized = normalize_text(scenario.source_text)
    source = SourceChunk(
        chunk_id=f"source:{scenario.scenario_id}:0",
        source_id=f"source:{scenario.scenario_id}",
        ordinal=0,
        text=scenario.source_text,
        normalized_text=source_normalized,
        text_hash=_text_hash(scenario.source_text),
        shingle_fingerprint=_shingle_fingerprint(source_normalized),
        token_count=estimate_token_count(source_normalized),
        workspace_id=workspace_id,
    )
    contexts = tuple(
        _make_artifact_context(
            scenario=scenario,
            text=text,
            sequence_no=index,
            workspace_id=workspace_id,
            session_id=session_id,
            workspace_root=workspace_root,
        )
        for index, text in enumerate(scenario.artifact_texts, start=1)
    )
    sink = SinkCandidate(
        node_id=f"sink:{scenario.scenario_id}",
        sink_type=scenario.sink_type,
        label=f"Similarity evaluation sink {scenario.scenario_id}",
        tool_name="synthetic_evaluation",
        tool_use_id=f"tool:{scenario.scenario_id}:sink",
        session_id=session_id,
        sequence_no=len(contexts) + 1,
        metadata={"provenance": "synthetic"},
        workspace_id=workspace_id,
    )
    sink_edge = make_submitted_to_edge(
        src_id=contexts[-1].fragment.fragment_id,
        sink_id=sink.node_id,
        method="synthetic_evaluation_sink",
        reason="dataset attaches the final artifact to its labeled sink",
    )
    return _ScenarioMaterial(
        source=source,
        contexts=contexts,
        sink=sink,
        sink_edge=sink_edge,
    )


def _make_artifact_context(
    *,
    scenario: LineageScenario,
    text: str,
    sequence_no: int,
    workspace_id: str,
    session_id: str,
    workspace_root: str,
) -> ArtifactContext:
    normalized = normalize_text(text)
    fragment_id = f"fragment:{scenario.scenario_id}:{sequence_no}"
    turn_id = f"turn:{scenario.scenario_id}"
    tool_use_id = f"tool:{scenario.scenario_id}:{sequence_no}"
    tool_name = "mcp__similarity_evaluation__submit"
    payload = {
        "session_id": session_id,
        "turn_id": turn_id,
        "tool_use_id": tool_use_id,
        "tool_name": tool_name,
        "provenance": "synthetic",
    }
    event_id = make_event_id("pre_tool_use", payload)
    return ArtifactContext(
        fragment=ArtifactFragment(
            fragment_id=fragment_id,
            artifact_id=f"artifact:{scenario.scenario_id}:{sequence_no}",
            json_pointer="/content",
            semantic_role="content",
            text=text,
            text_hash=_text_hash(text),
            normalized_text=normalized,
            token_count=estimate_token_count(normalized),
            fragment_kind="payload",
        ),
        artifact_role="tool_input",
        event_id=event_id,
        phase="pre_tool_use",
        session_id=session_id,
        turn_id=turn_id,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        cwd=workspace_root,
        sequence_no=sequence_no,
        workspace_id=workspace_id,
        workspace_root=workspace_root,
        workspace_lexical_root=workspace_root,
        workspace_execution_cwd=workspace_root,
        workspace_status="ready",
    )


def _run_full_scenario(
    scenario: LineageScenario,
    material: _ScenarioMaterial,
    *,
    minimum_path_score: float,
    finding_min_score: float,
) -> _ScenarioExecution:
    artifact_edges = tuple(build_artifact_flow_edges(list(material.contexts)))
    source_edges = tuple(
        build_source_binding_edges(
            [material.source],
            list(material.contexts),
            list(artifact_edges),
        )
    )
    assessment = _graph_outcome(
        scenario,
        material,
        artifact_edges,
        source_edges,
        minimum_path_score=minimum_path_score,
        finding_min_score=finding_min_score,
    )
    return _ScenarioExecution(
        outcome=assessment.outcome,
        artifact_edges=artifact_edges,
        source_edges=source_edges,
        assignment_signatures=assessment.assignment_signatures,
        finding_signatures=assessment.finding_signatures,
        decision_signatures=assessment.decision_signatures,
    )


def _run_incremental_scenario(
    scenario: LineageScenario,
    *,
    minimum_path_score: float,
    finding_min_score: float,
) -> _ScenarioExecution:
    with tempfile.TemporaryDirectory(
        prefix="tooluseproxy-similarity-incremental-"
    ) as temporary_directory:
        root = Path(temporary_directory) / "workspace"
        root.mkdir()
        workspace = resolve_workspace(str(root))
        if (
            not workspace.ready
            or workspace.workspace_id is None
            or workspace.canonical_root is None
        ):
            raise RuntimeError("cannot create synthetic incremental workspace")
        material = _make_scenario_material(
            scenario,
            workspace_id=workspace.workspace_id,
            workspace_root=workspace.canonical_root,
        )
        store = EventStore(Path(temporary_directory) / "events.db")
        store.initialize()
        artifact_edges: dict[str, FlowEdge] = {}
        source_edges: dict[str, FlowEdge] = {}
        assignments: dict[tuple[str, str, str, str], LineageAssignment] = {}
        analysis_run_id = f"similarity-evaluation:{scenario.scenario_id}"
        session_id = material.sink.session_id
        assert session_id is not None

        for index, context in enumerate(material.contexts):
            _record_evaluation_context(store, context)
            stored_contexts = store.list_artifact_contexts_for_scope_by_fragment_ids(
                workspace.workspace_id,
                session_id,
                {context.fragment.fragment_id},
            )
            if len(stored_contexts) != 1:
                raise RuntimeError("synthetic incremental context was not stored")
            current = stored_contexts[0]
            delta_artifact_edges = _build_delta_similarity_edges(
                store,
                workspace.workspace_id,
                session_id,
                [current],
            )
            for edge in delta_artifact_edges:
                artifact_edges[edge.edge_id] = edge

            predecessor_ids = {
                edge.src_node_id
                for edge in delta_artifact_edges
                if edge.src_node_kind == "artifact_fragment"
            }
            predecessor_contexts = (
                store.list_artifact_contexts_for_scope_by_fragment_ids(
                    workspace.workspace_id,
                    session_id,
                    predecessor_ids,
                )
                if predecessor_ids
                else []
            )
            delta_source_edges = build_source_binding_edges(
                [material.source],
                [current] + predecessor_contexts,
                delta_artifact_edges,
                target_fragment_ids={current.fragment.fragment_id},
            )
            for edge in delta_source_edges:
                source_edges[edge.edge_id] = edge

            delta_edges = list(delta_source_edges) + list(delta_artifact_edges)
            if index == len(material.contexts) - 1:
                delta_edges.append(material.sink_edge)
            changed = propagate_lineage_incremental(
                analysis_run_id,
                list(assignments.values()),
                delta_edges,
                minimum_path_score=minimum_path_score,
            )
            for assignment in changed:
                assignments[_assignment_key(assignment)] = assignment

        assessment = _outcome_from_assignments(
            scenario,
            material,
            list(assignments.values()),
            minimum_path_score=minimum_path_score,
            finding_min_score=finding_min_score,
        )
        return _ScenarioExecution(
            outcome=assessment.outcome,
            artifact_edges=tuple(artifact_edges.values()),
            source_edges=tuple(source_edges.values()),
            assignment_signatures=assessment.assignment_signatures,
            finding_signatures=assessment.finding_signatures,
            decision_signatures=assessment.decision_signatures,
        )


def _record_evaluation_context(store: EventStore, context: ArtifactContext) -> None:
    fragment = context.fragment
    event = NormalizedEvent(
        event_id=context.event_id,
        phase=context.phase,
        session_id=context.session_id,
        turn_id=context.turn_id,
        tool_use_id=context.tool_use_id,
        tool_name=context.tool_name,
        cwd=context.cwd,
        model=None,
        permission_mode=None,
        transcript_path=None,
        stop_hook_active=None,
        workspace_id=context.workspace_id,
        workspace_root=context.workspace_root,
        workspace_lexical_root=context.workspace_lexical_root,
        workspace_execution_cwd=context.workspace_execution_cwd,
        workspace_status=context.workspace_status,
        workspace_source="hook_cwd",
        workspace_namespace_id=None,
        raw_payload={
            "session_id": context.session_id,
            "turn_id": context.turn_id,
            "tool_use_id": context.tool_use_id,
            "tool_name": context.tool_name,
            "provenance": "synthetic",
        },
    )
    artifact = ArtifactRecord(
        artifact_id=fragment.artifact_id,
        event_id=context.event_id,
        role=context.artifact_role,
        text=fragment.text,
        text_hash=fragment.text_hash,
        normalized_text=fragment.normalized_text,
        token_count=fragment.token_count,
    )
    store.record(event, [artifact], [fragment])


def _graph_outcome(
    scenario: LineageScenario,
    material: _ScenarioMaterial,
    artifact_edges: Sequence[FlowEdge],
    source_edges: Sequence[FlowEdge],
    *,
    minimum_path_score: float,
    finding_min_score: float,
) -> _ScenarioAssessment:
    analysis_run_id = f"similarity-evaluation:{scenario.scenario_id}"
    assignments = propagate_lineage(
        analysis_run_id,
        list(source_edges) + list(artifact_edges) + [material.sink_edge],
        minimum_path_score=minimum_path_score,
    )
    return _outcome_from_assignments(
        scenario,
        material,
        assignments,
        minimum_path_score=minimum_path_score,
        finding_min_score=finding_min_score,
    )


def _outcome_from_assignments(
    scenario: LineageScenario,
    material: _ScenarioMaterial,
    assignments: list[LineageAssignment],
    *,
    minimum_path_score: float,
    finding_min_score: float,
) -> _ScenarioAssessment:
    analysis_run_id = f"similarity-evaluation:{scenario.scenario_id}"
    sink_assignments = [
        assignment
        for assignment in assignments
        if assignment.node_kind == "sink_candidate"
        and assignment.node_id == material.sink.node_id
    ]
    best_assignment = max(
        sink_assignments,
        key=lambda item: item.best_path_score,
        default=None,
    )
    analysis_run = AnalysisRun(
        analysis_run_id=analysis_run_id,
        detector_version=RUNNER_VERSION,
        config_json=json.dumps(
            {
                "minimum_path_score": minimum_path_score,
                "finding_min_score": finding_min_score,
            },
            sort_keys=True,
        ),
        started_at="synthetic",
        completed_at="synthetic",
        workspace_id=material.source.workspace_id,
        session_id=material.sink.session_id,
    )
    findings = detect_leaks(
        analysis_run=analysis_run,
        assignments=assignments,
        sink_candidates=[material.sink],
        min_score=finding_min_score,
        included_sink_types=(
            {"final_answer"} if scenario.sink_type == "final_answer" else None
        ),
    )
    decisions = evaluate_policy(findings)
    action = min(
        (decision.action for decision in decisions),
        key=lambda value: _ACTION_PRIORITY.get(value, 99),
        default="allow",
    )
    strongest_decision = min(
        decisions,
        key=lambda item: _ACTION_PRIORITY.get(item.action, 99),
        default=None,
    )
    return _ScenarioAssessment(
        outcome={
            "reached": best_assignment is not None,
            "finding_detected": bool(findings),
            "action": action,
            "severity": strongest_decision.severity if strongest_decision else None,
            "path_score": (
                round(best_assignment.best_path_score, 6)
                if best_assignment is not None
                else None
            ),
            "hop_count": (
                best_assignment.hop_count if best_assignment is not None else None
            ),
        },
        assignment_signatures=_assignment_signatures(assignments),
        finding_signatures=_finding_signatures(findings),
        decision_signatures=_decision_signatures(decisions),
    )


def _assignment_key(
    assignment: LineageAssignment,
) -> tuple[str, str, str, str]:
    return (
        assignment.source_node_kind,
        assignment.source_node_id,
        assignment.node_kind,
        assignment.node_id,
    )


def _compare_scenario_executions(
    scenario: LineageScenario,
    full: _ScenarioExecution,
    incremental: _ScenarioExecution,
) -> dict[str, Any]:
    artifact_equal = _edge_signatures(full.artifact_edges) == _edge_signatures(
        incremental.artifact_edges
    )
    source_equal = _edge_signatures(full.source_edges) == _edge_signatures(
        incremental.source_edges
    )
    assignments_equal = (
        full.assignment_signatures == incremental.assignment_signatures
    )
    findings_equal = full.finding_signatures == incremental.finding_signatures
    decisions_equal = full.decision_signatures == incremental.decision_signatures
    reachability_equal = full.outcome["reached"] == incremental.outcome["reached"]
    action_equal = full.outcome["action"] == incremental.outcome["action"]
    path_equal = (
        full.outcome["path_score"] == incremental.outcome["path_score"]
        and full.outcome["hop_count"] == incremental.outcome["hop_count"]
    )
    return {
        "id": scenario.scenario_id,
        "artifact_edges_equal": artifact_equal,
        "source_edges_equal": source_equal,
        "assignments_equal": assignments_equal,
        "findings_equal": findings_equal,
        "decisions_equal": decisions_equal,
        "reachability_equal": reachability_equal,
        "action_equal": action_equal,
        "path_equal": path_equal,
        "passed": (
            artifact_equal
            and source_equal
            and assignments_equal
            and findings_equal
            and decisions_equal
            and reachability_equal
            and action_equal
            and path_equal
        ),
    }


def _assignment_signatures(
    assignments: Sequence[LineageAssignment],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                assignment.analysis_run_id,
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
                finding.finding_id,
                finding.analysis_run_id,
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
                decision.decision_id,
                decision.action,
                decision.severity,
                decision.finding_id,
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


def _edge_signatures(edges: Sequence[FlowEdge]) -> tuple[tuple[Any, ...], ...]:
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


def _pair_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    all_metrics = _binary_summary(cases)
    gate_cases = [item for item in cases if not item["observe_only"]]
    by_scope = {
        scope: _binary_summary([item for item in cases if item["scope"] == scope])
        for scope in sorted({item["scope"] for item in cases})
    }
    by_family = {
        family: _binary_summary(
            [
                item
                for item in gate_cases
                if item["family"] == family
            ]
        )
        for family in sorted({item["family"] for item in gate_cases})
    }
    tags = sorted({tag for item in cases for tag in item["tags"]})
    by_tag = {
        tag: _binary_summary([item for item in cases if tag in item["tags"]])
        for tag in tags
    }
    methods = Counter(item["method"] for item in cases)
    scores_by_method: dict[str, dict[str, float | int]] = {}
    for method in sorted(methods):
        scores = [item["score"] for item in cases if item["method"] == method]
        scores_by_method[method] = {
            "count": len(scores),
            "min": min(scores),
            "p50": round(nearest_rank_percentile(scores, 0.50), 6),
            "p95": round(nearest_rank_percentile(scores, 0.95), 6),
            "max": max(scores),
        }
    return {
        "all": all_metrics,
        "gate": _binary_summary(gate_cases),
        "by_scope": by_scope,
        "by_family": by_family,
        "by_tag": by_tag,
        "counterfactuals": _counterfactual_metrics(gate_cases),
        "method_counts": dict(sorted(methods.items())),
        "score_by_method": scores_by_method,
        "score_semantics": (
            "Scores are the final SimilarityDecision values; current unmatched "
            "shingle comparisons return method=none and score=0."
        ),
    }


def _retrieval_metrics(
    cases: list[dict[str, Any]],
    *,
    dataset_schema_version: int,
) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for scope, limit in (
        ("artifact_flow", MAX_LEXICAL_CANDIDATES),
        ("source_binding", MAX_SOURCE_CANDIDATES),
    ):
        scoped = [item for item in cases if item["scope"] == scope]
        gate_scoped = [item for item in scoped if not item["observe_only"]]
        pool_size = max((int(item["pool_size"]) for item in scoped), default=0)
        saturated = [item for item in scoped if item["cap_saturated"]]
        gate_saturated = [item for item in gate_scoped if item["cap_saturated"]]
        metrics[scope] = {
            "limit": limit,
            "pool_size": pool_size,
            "pool_exceeds_limit": pool_size > limit,
            "saturated_case_count": sum(
                bool(item["cap_saturated"]) for item in scoped
            ),
            "saturation_rate": _safe_ratio(len(saturated), len(scoped)),
            "saturated": _retrieval_summary(saturated),
            "gate_saturated": _retrieval_summary(gate_saturated),
            "metric_name": f"candidate eligibility recall@{limit}",
            "implementation": "production_preparation_adapter_v2",
            "production_equivalence": (
                "Uses production primary exact keys and candidate features, then "
                "applies the shared coverage, overlap, candidate-ID rank with the "
                "same artifact exact priority and source exact-plus-lexical cap "
                "semantics."
            ),
            "corpus_scope": (
                "versioned_saturated_pool"
                if dataset_schema_version >= 2
                else "historical_pair_derived_pool"
            ),
            "all": _retrieval_summary(scoped),
            "gate": _retrieval_summary(gate_scoped),
            "by_family": {
                family: _retrieval_summary(
                    [item for item in gate_scoped if item["family"] == family]
                )
                for family in sorted(
                    {item["family"] for item in gate_scoped}
                )
            },
            "counterfactuals": _counterfactual_metrics(
                [
                    {
                        **item,
                        "expected": True,
                        "actual": item["retrieved_relevant"],
                    }
                    for item in gate_scoped
                ]
            ),
        }
    return metrics


def _retrieval_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    positives = [item for item in cases if item["relevant"]]
    retrieved = [item for item in positives if item["retrieved_relevant"]]
    counts = [float(item["candidate_count"]) for item in cases]
    return {
        "positive_cases": len(positives),
        "retrieved": len(retrieved),
        "recall": _safe_ratio(len(retrieved), len(positives)),
        "miss_ids": sorted(
            item["id"] for item in positives if not item["retrieved_relevant"]
        ),
        "candidate_sets_sha256": _outcomes_digest(
            b"tooluseproxy-similarity-candidate-sets-v1\0",
            [
                {
                    "id": item["id"],
                    "candidate_set_sha256": item["candidate_set_sha256"],
                }
                for item in cases
            ],
        ),
        "candidate_count_p50": (
            nearest_rank_percentile(counts, 0.50) if counts else 0.0
        ),
        "candidate_count_p95": (
            nearest_rank_percentile(counts, 0.95) if counts else 0.0
        ),
    }


def _end_to_end_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    gate_cases = [item for item in cases if not item["observe_only"]]
    return {
        "all": _scenario_summary(cases),
        "gate": _scenario_summary(gate_cases),
        "by_family": {
            family: _scenario_summary(
                [item for item in gate_cases if item["family"] == family]
            )
            for family in sorted({item["family"] for item in gate_cases})
        },
        "counterfactuals": _scenario_counterfactual_metrics(gate_cases),
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
    correct = 0
    for item in cases:
        action_matrix[item["expected_action"]][item["actual_action"]] += 1
        correct += item["expected_action"] == item["actual_action"]
    return {
        "case_count": len(cases),
        "reachability": _binary_summary(reach_cases),
        "action_accuracy": _safe_ratio(correct, len(cases)),
        "action_confusion": {
            expected: dict(sorted(actual.items()))
            for expected, actual in sorted(action_matrix.items())
        },
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
        "unexpected_reviews": sorted(
            item["id"]
            for item in cases
            if item["expected_action"] == "allow"
            and item["actual_action"] == "continue_review"
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


def _counterfactual_metrics(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in cases:
        group = item.get("counterfactual_group")
        if isinstance(group, str):
            grouped[group].append(item)
    failed: list[str] = []
    for group, items in grouped.items():
        if len(items) != 2 or not all(
            item["expected"] == item["actual"] for item in items
        ):
            failed.append(group)
    return {
        "group_count": len(grouped),
        "passed_groups": len(grouped) - len(failed),
        "accuracy": _safe_ratio(len(grouped) - len(failed), len(grouped)),
        "failed_group_ids": sorted(failed),
    }


def _scenario_counterfactual_metrics(
    cases: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in cases:
        group = item.get("counterfactual_group")
        if isinstance(group, str):
            grouped[group].append(item)
    failed = sorted(
        group
        for group, items in grouped.items()
        if len(items) != 2
        or not all(
            item["expected_reach"] == item["actual_reach"]
            and item["expected_action"] == item["actual_action"]
            for item in items
        )
    )
    return {
        "group_count": len(grouped),
        "passed_groups": len(grouped) - len(failed),
        "accuracy": _safe_ratio(len(grouped) - len(failed), len(grouped)),
        "failed_group_ids": failed,
    }


def _parity_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    mismatches = sorted(item["id"] for item in cases if not item["passed"])
    return {
        "implementation": "event_store_incremental_graph_v1",
        "scope": (
            "Compares full graph construction with the EventStore incremental "
            "candidate index, delta source binding, propagate_lineage_incremental, "
            "finding, and policy functions. Adapter extraction is outside this corpus."
        ),
        "case_count": len(cases),
        "passed": not mismatches,
        "mismatch_ids": mismatches,
    }


def _binary_summary(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(item["expected"] and item["actual"] for item in cases)
    fp = sum(not item["expected"] and item["actual"] for item in cases)
    tn = sum(not item["expected"] and not item["actual"] for item in cases)
    fn = sum(item["expected"] and not item["actual"] for item in cases)
    precision = _optional_ratio(tp, tp + fp)
    recall = _optional_ratio(tp, tp + fn)
    specificity = _optional_ratio(tn, tn + fp)
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
        "specificity": specificity,
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


def _finish_evaluation_contract(
    report: dict[str, Any],
    dataset: SimilarityDataset,
    *,
    split: str | None,
    pair_cases: Sequence[dict[str, Any]],
    retrieval_cases: Sequence[dict[str, Any]],
    scenario_cases: Sequence[dict[str, Any]],
    parity_metrics: dict[str, Any],
) -> None:
    pair_gate = report["metrics"]["pair_classification"]["gate"]
    retrieval = report["metrics"]["candidate_retrieval"]
    e2e_gate = report["metrics"]["end_to_end"]["gate"]
    action_correct = sum(
        int(item["expected_action"] == item["actual_action"])
        for item in scenario_cases
        if not item["observe_only"]
    )
    observed_baseline: dict[str, object] = {
        "pair_tp": pair_gate["tp"],
        "pair_fp": pair_gate["fp"],
        "pair_tn": pair_gate["tn"],
        "pair_fn": pair_gate["fn"],
        "artifact_candidate_positive_cases": retrieval["artifact_flow"]["gate"][
            "positive_cases"
        ],
        "artifact_candidate_retrieved": retrieval["artifact_flow"]["gate"][
            "retrieved"
        ],
        "source_candidate_positive_cases": retrieval["source_binding"]["gate"][
            "positive_cases"
        ],
        "source_candidate_retrieved": retrieval["source_binding"]["gate"][
            "retrieved"
        ],
        "e2e_tp": e2e_gate["reachability"]["tp"],
        "e2e_fp": e2e_gate["reachability"]["fp"],
        "e2e_tn": e2e_gate["reachability"]["tn"],
        "e2e_fn": e2e_gate["reachability"]["fn"],
        "e2e_action_correct": action_correct,
        "e2e_action_cases": e2e_gate["case_count"],
        "parity_mismatches": len(parity_metrics["mismatch_ids"]),
        "pair_outcomes_sha256": _outcomes_digest(
            b"tooluseproxy-similarity-pair-outcomes-v2\0",
            [
                {
                    "id": item["id"],
                    "expected": item["expected"],
                    "actual": item["actual"],
                    "method": item["method"],
                    "score": item["score"],
                }
                for item in pair_cases
            ],
        ),
        "candidate_outcomes_sha256": _outcomes_digest(
            b"tooluseproxy-similarity-candidate-outcomes-v2\0",
            [
                {
                    "id": item["id"],
                    "retrieved_relevant": item["retrieved_relevant"],
                    "candidate_count": item["candidate_count"],
                    "pool_size": item["pool_size"],
                }
                for item in retrieval_cases
            ],
        ),
        "scenario_outcomes_sha256": _outcomes_digest(
            b"tooluseproxy-similarity-scenario-outcomes-v2\0",
            [
                {
                    "id": item["id"],
                    "actual_reach": item["actual_reach"],
                    "actual_action": item["actual_action"],
                    "path_score": item["path_score"],
                    "hop_count": item["hop_count"],
                }
                for item in scenario_cases
            ],
        ),
        "privacy_exposures": 0,
    }
    expected_baseline = dataset.select_baseline(split)
    privacy = _privacy_metrics(
        dataset,
        report,
        extra_surface={
            "expected_baseline": expected_baseline,
            "observed_baseline": observed_baseline,
        },
    )
    observed_baseline["privacy_exposures"] = privacy["total_exposure_count"]
    baseline_reproduced = (
        observed_baseline == expected_baseline
        if expected_baseline is not None
        else report["dataset"]["digest_matches_pinned"]
    )
    caps_exercised = all(
        retrieval[scope]["saturated_case_count"] > 0
        for scope in ("artifact_flow", "source_binding")
    )
    v2_contract = dataset.schema_version >= 2
    invariants = {
        "dataset_digest_matches_pinned": report["dataset"][
            "digest_matches_pinned"
        ],
        "baseline_reproduced": baseline_reproduced,
        "privacy_passed": privacy["total_exposure_count"] == 0,
        "full_incremental_parity": parity_metrics["passed"],
        "artifact_and_source_caps_exercised": (
            caps_exercised if v2_contract else True
        ),
        "versioned_family_contract_loaded": (
            dataset.family_contract is not None if v2_contract else True
        ),
        "split_vocabulary_and_shape_contract_loaded": (
            dataset.split_contract is not None if v2_contract else True
        ),
    }
    report["metrics"]["privacy"] = privacy
    report["metrics"]["invariants"] = {
        **invariants,
        "passed": all(invariants.values()),
    }
    report["baseline"] = {
        "expected": expected_baseline,
        "observed": observed_baseline,
        "reproduced": baseline_reproduced,
    }
    quality = _go_no_go_assessment(report, dataset.go_no_go)
    report["quality"] = quality
    report["summary"].update(
        {
            "baseline_reproduced": baseline_reproduced,
            "privacy_passed": privacy["total_exposure_count"] == 0,
            "invariants_passed": all(invariants.values()),
            "check_passed": all(invariants.values()),
            "go_no_go_available": dataset.go_no_go is not None,
            "go_no_go_passed": quality["passed"],
            "status": "go" if quality["passed"] else "no_go",
        }
    )


def _privacy_metrics(
    dataset: SimilarityDataset,
    report: dict[str, Any],
    *,
    extra_surface: object | None = None,
) -> dict[str, int]:
    serialized = json.dumps(
        {"report": report, "extra_surface": extra_surface},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    fixture_texts = _fixture_texts(dataset)
    body_probe_texts = tuple(
        text
        for text in fixture_texts
        if _is_privacy_body_probe(text)
    )
    body_exposures = sum(text in serialized for text in body_probe_texts)
    body_hash_exposures = sum(
        hashlib.sha256(text.encode("utf-8")).hexdigest() in serialized
        for text in fixture_texts
    )
    return {
        "fixture_body_probe_count": len(body_probe_texts),
        "fixture_hash_probe_count": len(fixture_texts),
        "fixture_body_exposure_count": body_exposures,
        "fixture_body_hash_exposure_count": body_hash_exposures,
        "total_exposure_count": body_exposures + body_hash_exposures,
    }


def _is_privacy_body_probe(text: str) -> bool:
    if len(text) >= _MIN_PRIVACY_BODY_PROBE_LENGTH:
        return True
    if _PRIVACY_CANARY_PATTERN.search(text) is not None:
        return True
    stripped = text.strip()
    return (
        len(stripped) >= 8
        and any(character.isalpha() for character in stripped)
        and any(character.isdigit() for character in stripped)
        and len(set(stripped.casefold())) >= 6
    )


def _fixture_texts(dataset: SimilarityDataset) -> tuple[str, ...]:
    texts = {
        text
        for pair in dataset.pairs
        for text in (pair.left_text, pair.right_text)
    }
    texts.update(scenario.source_text for scenario in dataset.scenarios)
    texts.update(
        text
        for scenario in dataset.scenarios
        for text in scenario.artifact_texts
    )
    texts.update(pool.query_text for pool in dataset.retrieval_pools)
    texts.update(
        candidate.text
        for pool in dataset.retrieval_pools
        for candidate in pool.candidates
    )
    return tuple(sorted(texts))


def _go_no_go_assessment(
    report: dict[str, Any],
    thresholds: dict[str, float] | None,
) -> dict[str, Any]:
    if thresholds is None:
        return {
            "available": False,
            "passed": False,
            "checks": {},
            "minimum_family_accuracy": 0.0,
        }
    pair = report["metrics"]["pair_classification"]
    retrieval = report["metrics"]["candidate_retrieval"]
    e2e = report["metrics"]["end_to_end"]
    family_scores: list[float] = []
    for metrics in pair["by_family"].values():
        family_scores.append(float(metrics["accuracy"]))
    for scope in ("artifact_flow", "source_binding"):
        for metrics in retrieval[scope]["by_family"].values():
            family_scores.append(float(metrics["recall"]))
    for metrics in e2e["by_family"].values():
        family_scores.extend(
            (
                float(metrics["reachability"]["accuracy"]),
                float(metrics["action_accuracy"]),
            )
        )
    minimum_family_accuracy = min(family_scores, default=0.0)
    pair_gate = pair["gate"]
    e2e_gate = e2e["gate"]
    values = {
        "minimum_pair_precision": float(pair_gate["precision"] or 0.0),
        "minimum_pair_recall": float(pair_gate["recall"] or 0.0),
        "minimum_pair_f1": float(pair_gate["f1"] or 0.0),
        "minimum_artifact_candidate_recall": float(
            retrieval["artifact_flow"]["gate"]["recall"]
        ),
        "minimum_source_candidate_recall": float(
            retrieval["source_binding"]["gate"]["recall"]
        ),
        "minimum_e2e_reachability_f1": float(
            e2e_gate["reachability"]["f1"] or 0.0
        ),
        "minimum_e2e_action_accuracy": float(e2e_gate["action_accuracy"]),
        "minimum_family_accuracy": minimum_family_accuracy,
        "maximum_false_blocks": float(len(e2e_gate["false_blocks"])),
        "maximum_privacy_exposures": float(
            report["metrics"]["privacy"]["total_exposure_count"]
        ),
    }
    checks = {
        key: (
            values[key] <= threshold
            if key.startswith("maximum_")
            else values[key] >= threshold
        )
        for key, threshold in thresholds.items()
    }
    return {
        "available": True,
        "passed": all(checks.values()),
        "checks": dict(sorted(checks.items())),
        "observed": values,
        "thresholds": dict(sorted(thresholds.items())),
        "minimum_family_accuracy": minimum_family_accuracy,
    }


def _outcomes_digest(domain: bytes, payload: object) -> str:
    digest = hashlib.sha256(domain)
    digest.update(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )
    return digest.hexdigest()


def _benchmark(
    pairs: Sequence[PairExample],
    scenarios: Sequence[LineageScenario],
    *,
    retrieval_pools: Sequence[RetrievalPool],
    benchmark_repeats: int,
    minimum_path_score: float,
    finding_min_score: float,
) -> dict[str, dict[str, float | int]]:
    samples: dict[str, list[int]] = defaultdict(list)
    candidates_by_scope = {
        scope: [
            RetrievalCandidate(
                pair.example_id,
                pair.left_text if scope == "artifact_flow" else pair.right_text,
                index,
            )
            for index, pair in enumerate(
                [item for item in pairs if item.scope == scope],
                start=1,
            )
        ]
        for scope in SUPPORTED_PAIR_SCOPES
    }
    for _repeat in range(benchmark_repeats):
        for pair in pairs:
            samples["pair"].append(_timed_ns(lambda pair=pair: _compare_pair(pair)))
            if not retrieval_pools:
                samples[f"{pair.scope.split('_')[0]}_retrieval"].append(
                    _timed_ns(
                        lambda pair=pair: simulate_candidate_retrieval(
                            scope=pair.scope,
                            query_text=(
                                pair.right_text
                                if pair.scope == "artifact_flow"
                                else pair.left_text
                            ),
                            candidates=candidates_by_scope[pair.scope],
                        )
                    )
                )
        for pool in retrieval_pools:
            candidates = tuple(
                RetrievalCandidate(
                    item.candidate_id,
                    item.text,
                    item.sequence_no,
                )
                for item in pool.candidates
            )
            samples[f"{pool.scope.split('_')[0]}_retrieval"].append(
                _timed_ns(
                    lambda pool=pool, candidates=candidates: (
                        simulate_candidate_retrieval(
                            scope=pool.scope,
                            query_text=pool.query_text,
                            candidates=candidates,
                        )
                    )
                )
            )
        for scenario in scenarios:
            material = _make_scenario_material(scenario)
            samples["e2e_full"].append(
                _timed_ns(
                    lambda scenario=scenario, material=material: _run_full_scenario(
                        scenario,
                        material,
                        minimum_path_score=minimum_path_score,
                        finding_min_score=finding_min_score,
                    )
                )
            )
            samples["e2e_incremental"].append(
                _timed_ns(
                    lambda scenario=scenario: _run_incremental_scenario(
                        scenario,
                        minimum_path_score=minimum_path_score,
                        finding_min_score=finding_min_score,
                    )
                )
            )
    return {
        name: _latency_summary(samples[name])
        for name in (
            "pair",
            "artifact_retrieval",
            "source_retrieval",
            "e2e_full",
            "e2e_incremental",
        )
    }


def _timed_ns(operation: Callable[[], object]) -> int:
    started = time.perf_counter_ns()
    operation()
    return time.perf_counter_ns() - started


def _latency_summary(samples_ns: Sequence[int]) -> dict[str, float | int]:
    samples_ms = [sample / 1_000_000 for sample in samples_ns]
    if not samples_ms:
        return {"samples": 0, "p50": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "samples": len(samples_ms),
        "p50": round(nearest_rank_percentile(samples_ms, 0.50), 6),
        "p95": round(nearest_rank_percentile(samples_ms, 0.95), 6),
        "max": round(max(samples_ms), 6),
    }


def _safe_ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _optional_ratio(numerator: float, denominator: float) -> float | None:
    return _safe_ratio(numerator, denominator) if denominator else None


def _format_ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _shingle_fingerprint(normalized_text: str) -> str:
    serialized = "\0".join(sorted(make_shingles(normalized_text)))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
