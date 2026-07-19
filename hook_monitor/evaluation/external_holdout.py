from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from hook_monitor.evaluation.dataset import (
    LineageScenario,
    PairExample,
    SUPPORTED_ACTIONS,
    SUPPORTED_SINK_TYPES,
)
from hook_monitor.evaluation.similarity import (
    DEFAULT_FINDING_MIN_SCORE,
    DEFAULT_MINIMUM_PATH_SCORE,
    _compare_pair,
    _compare_scenario_executions,
    _make_scenario_material,
    _run_full_scenario,
    _run_incremental_scenario,
    nearest_rank_percentile,
)
from hook_monitor.runtime.source_binding import SOURCE_BINDING_SIGNALS


EXTERNAL_HOLDOUT_CONTRACT = "tooluseproxy-similarity-external-holdout"
EXTERNAL_HOLDOUT_CONTRACT_VERSION = "1.0.0"
EXTERNAL_HOLDOUT_SCHEMA_VERSION = 1
EXTERNAL_HOLDOUT_REPORT_SCHEMA_VERSION = 1
EXTERNAL_HOLDOUT_RUNNER_VERSION = "similarity-external-holdout-v1"
EXTERNAL_HOLDOUT_MANIFEST = "manifest.json"
EXTERNAL_HOLDOUT_CASES = "cases.jsonl"

MAX_HOLDOUT_FILE_BYTES = 16 * 1024 * 1024
MAX_HOLDOUT_CASES_PER_KIND = 1_000
MAX_HOLDOUT_TEXT_BYTES = 64 * 1024
MAX_HOLDOUT_ARTIFACTS = 8
MIN_HOLDOUT_CASES_PER_CATEGORY_KIND = 2
MAX_HOLDOUT_BENCHMARK_OPERATIONS = 10_000

_PUBLIC_CATEGORY_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "contract_version",
        "public_categories",
        "expected_counts",
        "attestation",
    }
)
_EXPECTED_COUNT_KEYS = frozenset({"pairs", "scenarios"})
_ATTESTATION_KEYS = frozenset(
    {"contains_live_credentials", "categories_are_public"}
)
_COMMON_CASE_KEYS = frozenset(
    {"schema_version", "kind", "public_category", "source_binding_signal"}
)
_PAIR_KEYS = _COMMON_CASE_KEYS | frozenset(
    {"left_text", "right_text", "should_link"}
)
_SCENARIO_KEYS = _COMMON_CASE_KEYS | frozenset(
    {
        "source_text",
        "artifact_texts",
        "sink_type",
        "should_reach_sink",
        "expected_action",
    }
)
_PRIVATE_TEXT_MIN_CHARS = 8


class ExternalHoldoutError(ValueError):
    def __init__(self, code: str, *, record_number: int | None = None) -> None:
        self.code = code
        self.record_number = record_number
        location = (
            f" at record {record_number}" if record_number is not None else ""
        )
        super().__init__(f"{code}{location}")


@dataclass(frozen=True)
class ExternalHoldoutCase:
    public_category: str
    pair: PairExample | None = None
    scenario: LineageScenario | None = None


@dataclass(frozen=True)
class ExternalHoldoutDataset:
    public_categories: tuple[str, ...]
    cases: tuple[ExternalHoldoutCase, ...]
    private_texts: tuple[str, ...]
    private_root: Path

    @property
    def pairs(self) -> tuple[ExternalHoldoutCase, ...]:
        return tuple(case for case in self.cases if case.pair is not None)

    @property
    def scenarios(self) -> tuple[ExternalHoldoutCase, ...]:
        return tuple(case for case in self.cases if case.scenario is not None)


def load_external_holdout(
    root: Path,
    *,
    forbidden_repository_root: Path,
) -> ExternalHoldoutDataset:
    private_root = root.expanduser().resolve(strict=False)
    repository_root = forbidden_repository_root.expanduser().resolve(strict=True)
    if private_root == repository_root or private_root.is_relative_to(repository_root):
        raise ExternalHoldoutError("holdout_must_be_outside_repository")
    if not private_root.is_dir():
        raise ExternalHoldoutError("holdout_directory_missing")

    manifest_path = private_root / EXTERNAL_HOLDOUT_MANIFEST
    cases_path = private_root / EXTERNAL_HOLDOUT_CASES
    manifest = _read_manifest(manifest_path)
    categories, expected_counts = _parse_manifest(manifest)
    records = _read_cases(cases_path)

    cases: list[ExternalHoldoutCase] = []
    private_texts: list[str] = []
    pair_index = 0
    scenario_index = 0
    for record_number, record in enumerate(records, start=1):
        kind = record.get("kind")
        if kind == "pair":
            pair_index += 1
            case, texts = _parse_pair_case(
                record,
                record_number=record_number,
                ordinal=pair_index,
                categories=categories,
            )
        elif kind == "scenario":
            scenario_index += 1
            case, texts = _parse_scenario_case(
                record,
                record_number=record_number,
                ordinal=scenario_index,
                categories=categories,
            )
        else:
            raise ExternalHoldoutError(
                "case_kind_invalid",
                record_number=record_number,
            )
        cases.append(case)
        private_texts.extend(texts)

    if pair_index != expected_counts["pairs"]:
        raise ExternalHoldoutError("pair_count_mismatch")
    if scenario_index != expected_counts["scenarios"]:
        raise ExternalHoldoutError("scenario_count_mismatch")
    if pair_index > MAX_HOLDOUT_CASES_PER_KIND:
        raise ExternalHoldoutError("pair_count_limit_exceeded")
    if scenario_index > MAX_HOLDOUT_CASES_PER_KIND:
        raise ExternalHoldoutError("scenario_count_limit_exceeded")
    _validate_category_coverage(cases, categories)
    _validate_label_coverage(cases)
    return ExternalHoldoutDataset(
        public_categories=categories,
        cases=tuple(cases),
        private_texts=tuple(private_texts),
        private_root=private_root,
    )


def evaluate_external_holdout(
    dataset: ExternalHoldoutDataset,
    *,
    benchmark_repeats: int = 1,
    minimum_path_score: float = DEFAULT_MINIMUM_PATH_SCORE,
    finding_min_score: float = DEFAULT_FINDING_MIN_SCORE,
) -> dict[str, Any]:
    if not isinstance(benchmark_repeats, int) or isinstance(benchmark_repeats, bool):
        raise ExternalHoldoutError("benchmark_repeats_invalid")
    if not 1 <= benchmark_repeats <= 100:
        raise ExternalHoldoutError("benchmark_repeats_invalid")
    benchmark_operations = benchmark_repeats * (
        len(dataset.pairs) + 2 * len(dataset.scenarios)
    )
    if benchmark_operations > MAX_HOLDOUT_BENCHMARK_OPERATIONS:
        raise ExternalHoldoutError("benchmark_work_limit_exceeded")
    if not 0.0 <= minimum_path_score <= 1.0:
        raise ExternalHoldoutError("minimum_path_score_invalid")
    if not 0.0 <= finding_min_score <= 1.0:
        raise ExternalHoldoutError("finding_min_score_invalid")

    pair_results: list[dict[str, Any]] = []
    scenario_results: list[dict[str, Any]] = []
    parity_results: list[dict[str, Any]] = []
    latency_samples: dict[str, list[int]] = defaultdict(list)

    try:
        for case in dataset.pairs:
            assert case.pair is not None
            decision, elapsed = _timed(
                lambda pair=case.pair: _compare_pair(
                    pair,
                    source_signals_enabled=True,
                )
            )
            latency_samples["pair"].append(elapsed)
            pair_results.append(
                {
                    "public_category": case.public_category,
                    "expected": case.pair.should_link,
                    "actual": decision.matched,
                    "method": decision.method,
                }
            )
            for _repeat in range(benchmark_repeats - 1):
                _unused, elapsed = _timed(
                    lambda pair=case.pair: _compare_pair(
                        pair,
                        source_signals_enabled=True,
                    )
                )
                latency_samples["pair"].append(elapsed)

        for case in dataset.scenarios:
            assert case.scenario is not None
            material = _make_scenario_material(
                case.scenario,
                source_signals_enabled=True,
            )
            full, elapsed = _timed(
                lambda scenario=case.scenario, material=material: _run_full_scenario(
                    scenario,
                    material,
                    minimum_path_score=minimum_path_score,
                    finding_min_score=finding_min_score,
                )
            )
            latency_samples["e2e_full"].append(elapsed)
            incremental, elapsed = _timed(
                lambda scenario=case.scenario: _run_incremental_scenario(
                    scenario,
                    minimum_path_score=minimum_path_score,
                    finding_min_score=finding_min_score,
                    source_signals_enabled=True,
                )
            )
            latency_samples["e2e_incremental"].append(elapsed)
            parity = _compare_scenario_executions(case.scenario, full, incremental)
            scenario_results.append(
                {
                    "public_category": case.public_category,
                    "expected_reach": case.scenario.should_reach_sink,
                    "actual_reach": full.outcome["reached"],
                    "expected_action": case.scenario.expected_action,
                    "actual_action": full.outcome["action"],
                }
            )
            parity_results.append(
                {
                    "public_category": case.public_category,
                    "passed": parity["passed"],
                }
            )
            for _repeat in range(benchmark_repeats - 1):
                _unused, elapsed = _timed(
                    lambda scenario=case.scenario, material=material: _run_full_scenario(
                        scenario,
                        material,
                        minimum_path_score=minimum_path_score,
                        finding_min_score=finding_min_score,
                    )
                )
                latency_samples["e2e_full"].append(elapsed)
                _unused, elapsed = _timed(
                    lambda scenario=case.scenario: _run_incremental_scenario(
                        scenario,
                        minimum_path_score=minimum_path_score,
                        finding_min_score=finding_min_score,
                        source_signals_enabled=True,
                    )
                )
                latency_samples["e2e_incremental"].append(elapsed)
    except ExternalHoldoutError:
        raise
    except Exception:
        raise ExternalHoldoutError("evaluation_failed") from None

    pair_metrics = _pair_metrics(pair_results, dataset.public_categories)
    scenario_metrics = _scenario_metrics(
        scenario_results,
        dataset.public_categories,
    )
    parity_metrics = _parity_metrics(parity_results, dataset.public_categories)
    report: dict[str, Any] = {
        "schema_version": EXTERNAL_HOLDOUT_REPORT_SCHEMA_VERSION,
        "runner_version": EXTERNAL_HOLDOUT_RUNNER_VERSION,
        "contract": {
            "name": EXTERNAL_HOLDOUT_CONTRACT,
            "version": EXTERNAL_HOLDOUT_CONTRACT_VERSION,
            "aggregate_only": True,
        },
        "counts": {
            "pairs": len(pair_results),
            "scenarios": len(scenario_results),
            "public_categories": len(dataset.public_categories),
        },
        "metrics": {
            "pair_classification": pair_metrics,
            "end_to_end": scenario_metrics,
            "full_incremental_parity": parity_metrics,
            "latency_ms": {
                name: _latency_summary(samples)
                for name, samples in sorted(latency_samples.items())
            },
        },
    }
    privacy = _privacy_audit(dataset, report)
    report["privacy"] = privacy
    quality = _quality_assessment(report)
    report["quality"] = quality
    report["summary"] = {
        "status": "go" if quality["passed"] else "no_go",
        "quality_passed": quality["passed"],
        "parity_passed": parity_metrics["passed"],
        "privacy_passed": privacy["passed"],
    }
    final_privacy = _privacy_audit(dataset, report)
    if not final_privacy["passed"]:
        raise ExternalHoldoutError("aggregate_report_privacy_violation")
    report["privacy"] = final_privacy
    return report


def render_external_holdout_report(report: dict[str, Any]) -> str:
    pair = report["metrics"]["pair_classification"]["overall"]
    e2e = report["metrics"]["end_to_end"]["overall"]
    parity = report["metrics"]["full_incremental_parity"]
    latency = report["metrics"]["latency_ms"]
    failed = [
        name for name, passed in report["quality"]["checks"].items() if not passed
    ]
    return "\n".join(
        (
            (
                f"external holdout runner={report['runner_version']} "
                f"contract={report['contract']['version']} aggregate_only=true"
            ),
            (
                f"pairs={report['counts']['pairs']} scenarios={report['counts']['scenarios']} "
                f"public_categories={report['counts']['public_categories']}"
            ),
            (
                f"pair precision={_metric(pair['precision'])} "
                f"recall={_metric(pair['recall'])} f1={_metric(pair['f1'])} "
                f"tp={pair['tp']} fp={pair['fp']} tn={pair['tn']} fn={pair['fn']}"
            ),
            (
                f"e2e reachability_f1={_metric(e2e['reachability']['f1'])} "
                f"action_accuracy={e2e['action_accuracy']:.3f} "
                f"false_blocks={e2e['false_blocks']} missed_blocks={e2e['missed_blocks']}"
            ),
            (
                f"full/incremental parity={'PASS' if parity['passed'] else 'FAIL'} "
                f"cases={parity['case_count']} mismatches={parity['mismatch_count']}"
            ),
            (
                "latency p95 ms "
                + " ".join(
                    f"{name}={values['p95']:.3f}"
                    for name, values in sorted(latency.items())
                )
            ),
            (
                f"privacy={'PASS' if report['privacy']['passed'] else 'FAIL'} "
                f"quality={'PASS' if report['quality']['passed'] else 'FAIL'} "
                f"failed={','.join(failed) if failed else 'none'}"
            ),
        )
    )


def _read_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ExternalHoldoutError("manifest_symlink_not_allowed")
    try:
        size = path.stat().st_size
    except OSError:
        raise ExternalHoldoutError("manifest_missing") from None
    if size > MAX_HOLDOUT_FILE_BYTES:
        raise ExternalHoldoutError("manifest_size_limit_exceeded")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ExternalHoldoutError("manifest_invalid") from None
    if not isinstance(value, dict):
        raise ExternalHoldoutError("manifest_invalid")
    return value


def _parse_manifest(value: dict[str, Any]) -> tuple[tuple[str, ...], dict[str, int]]:
    if set(value) != _MANIFEST_KEYS:
        raise ExternalHoldoutError("manifest_keys_invalid")
    if value["schema_version"] != EXTERNAL_HOLDOUT_SCHEMA_VERSION:
        raise ExternalHoldoutError("schema_version_unsupported")
    if value["contract"] != EXTERNAL_HOLDOUT_CONTRACT:
        raise ExternalHoldoutError("contract_invalid")
    if value["contract_version"] != EXTERNAL_HOLDOUT_CONTRACT_VERSION:
        raise ExternalHoldoutError("contract_version_unsupported")

    raw_categories = value["public_categories"]
    if (
        not isinstance(raw_categories, list)
        or not 2 <= len(raw_categories) <= 16
        or any(
            not isinstance(category, str)
            or _PUBLIC_CATEGORY_PATTERN.fullmatch(category) is None
            for category in raw_categories
        )
        or len(set(raw_categories)) != len(raw_categories)
    ):
        raise ExternalHoldoutError("public_categories_invalid")
    categories = tuple(raw_categories)

    expected = value["expected_counts"]
    if not isinstance(expected, dict) or set(expected) != _EXPECTED_COUNT_KEYS:
        raise ExternalHoldoutError("expected_counts_invalid")
    if any(
        not isinstance(expected[key], int)
        or isinstance(expected[key], bool)
        or expected[key] < len(categories) * MIN_HOLDOUT_CASES_PER_CATEGORY_KIND
        or expected[key] > MAX_HOLDOUT_CASES_PER_KIND
        for key in _EXPECTED_COUNT_KEYS
    ):
        raise ExternalHoldoutError("expected_counts_invalid")

    attestation = value["attestation"]
    if not isinstance(attestation, dict) or set(attestation) != _ATTESTATION_KEYS:
        raise ExternalHoldoutError("attestation_invalid")
    if attestation["contains_live_credentials"] is not False:
        raise ExternalHoldoutError("live_credentials_not_allowed")
    if attestation["categories_are_public"] is not True:
        raise ExternalHoldoutError("public_category_attestation_required")
    return categories, {key: int(expected[key]) for key in _EXPECTED_COUNT_KEYS}


def _read_cases(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise ExternalHoldoutError("cases_symlink_not_allowed")
    try:
        payload = path.read_bytes()
    except OSError:
        raise ExternalHoldoutError("cases_missing") from None
    if len(payload) > MAX_HOLDOUT_FILE_BYTES:
        raise ExternalHoldoutError("cases_size_limit_exceeded")
    try:
        text = payload.decode("utf-8")
    except UnicodeError:
        raise ExternalHoldoutError("cases_encoding_invalid") from None
    records: list[dict[str, Any]] = []
    fingerprints: set[str] = set()
    for record_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise ExternalHoldoutError(
                "blank_case_record",
                record_number=record_number,
            )
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise ExternalHoldoutError(
                "case_json_invalid",
                record_number=record_number,
            ) from None
        if not isinstance(record, dict):
            raise ExternalHoldoutError(
                "case_shape_invalid",
                record_number=record_number,
            )
        fingerprint = hashlib.sha256(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if fingerprint in fingerprints:
            raise ExternalHoldoutError(
                "duplicate_case_record",
                record_number=record_number,
            )
        fingerprints.add(fingerprint)
        records.append(record)
    return records


def _parse_pair_case(
    record: dict[str, Any],
    *,
    record_number: int,
    ordinal: int,
    categories: tuple[str, ...],
) -> tuple[ExternalHoldoutCase, tuple[str, ...]]:
    _validate_case_header(record, _PAIR_KEYS, record_number, categories)
    left = _private_text(record.get("left_text"), record_number)
    right = _private_text(record.get("right_text"), record_number)
    should_link = record.get("should_link")
    if not isinstance(should_link, bool):
        raise ExternalHoldoutError(
            "pair_label_invalid",
            record_number=record_number,
        )
    category = str(record["public_category"])
    pair = PairExample(
        example_id=f"external-pair-{ordinal:06d}",
        split="validation",
        scope="source_binding",
        left_text=left,
        right_text=right,
        should_link=should_link,
        observe_only=False,
        tags=(),
        rationale="private external holdout",
        family=category,
        source_binding_signal=str(record["source_binding_signal"]),
    )
    return ExternalHoldoutCase(category, pair=pair), (left, right)


def _parse_scenario_case(
    record: dict[str, Any],
    *,
    record_number: int,
    ordinal: int,
    categories: tuple[str, ...],
) -> tuple[ExternalHoldoutCase, tuple[str, ...]]:
    _validate_case_header(record, _SCENARIO_KEYS, record_number, categories)
    source = _private_text(record.get("source_text"), record_number)
    raw_artifacts = record.get("artifact_texts")
    if (
        not isinstance(raw_artifacts, list)
        or not 1 <= len(raw_artifacts) <= MAX_HOLDOUT_ARTIFACTS
    ):
        raise ExternalHoldoutError(
            "scenario_artifacts_invalid",
            record_number=record_number,
        )
    artifacts = tuple(
        _private_text(value, record_number) for value in raw_artifacts
    )
    sink_type = record.get("sink_type")
    if sink_type not in SUPPORTED_SINK_TYPES:
        raise ExternalHoldoutError(
            "scenario_sink_type_invalid",
            record_number=record_number,
        )
    should_reach = record.get("should_reach_sink")
    if not isinstance(should_reach, bool):
        raise ExternalHoldoutError(
            "scenario_reach_label_invalid",
            record_number=record_number,
        )
    expected_action = record.get("expected_action")
    if expected_action not in SUPPORTED_ACTIONS:
        raise ExternalHoldoutError(
            "scenario_action_invalid",
            record_number=record_number,
        )
    category = str(record["public_category"])
    scenario = LineageScenario(
        scenario_id=f"external-scenario-{ordinal:06d}",
        split="validation",
        source_text=source,
        artifact_texts=artifacts,
        sink_type=str(sink_type),
        should_reach_sink=should_reach,
        expected_action=str(expected_action),
        observe_only=False,
        tags=(),
        rationale="private external holdout",
        family=category,
        source_binding_signal=str(record["source_binding_signal"]),
    )
    return ExternalHoldoutCase(category, scenario=scenario), (source, *artifacts)


def _validate_case_header(
    record: dict[str, Any],
    expected_keys: frozenset[str],
    record_number: int,
    categories: tuple[str, ...],
) -> None:
    if set(record) != expected_keys:
        raise ExternalHoldoutError(
            "case_keys_invalid",
            record_number=record_number,
        )
    if record.get("schema_version") != EXTERNAL_HOLDOUT_SCHEMA_VERSION:
        raise ExternalHoldoutError(
            "case_schema_version_unsupported",
            record_number=record_number,
        )
    if record.get("public_category") not in categories:
        raise ExternalHoldoutError(
            "case_public_category_invalid",
            record_number=record_number,
        )
    signal = record.get("source_binding_signal")
    if signal not in SOURCE_BINDING_SIGNALS or signal == "not_applicable":
        raise ExternalHoldoutError(
            "case_source_binding_signal_invalid",
            record_number=record_number,
        )


def _private_text(value: object, record_number: int) -> str:
    if not isinstance(value, str) or len(value) < _PRIVATE_TEXT_MIN_CHARS:
        raise ExternalHoldoutError(
            "private_text_invalid",
            record_number=record_number,
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ExternalHoldoutError(
            "private_text_encoding_invalid",
            record_number=record_number,
        ) from None
    if len(encoded) > MAX_HOLDOUT_TEXT_BYTES or "\x00" in value:
        raise ExternalHoldoutError(
            "private_text_limit_exceeded",
            record_number=record_number,
        )
    return value


def _validate_category_coverage(
    cases: Sequence[ExternalHoldoutCase],
    categories: tuple[str, ...],
) -> None:
    for category in categories:
        pair_count = sum(
            case.public_category == category and case.pair is not None
            for case in cases
        )
        scenario_count = sum(
            case.public_category == category and case.scenario is not None
            for case in cases
        )
        if (
            pair_count < MIN_HOLDOUT_CASES_PER_CATEGORY_KIND
            or scenario_count < MIN_HOLDOUT_CASES_PER_CATEGORY_KIND
        ):
            raise ExternalHoldoutError("public_category_coverage_insufficient")


def _validate_label_coverage(cases: Sequence[ExternalHoldoutCase]) -> None:
    pair_labels = {
        case.pair.should_link for case in cases if case.pair is not None
    }
    reach_labels = {
        case.scenario.should_reach_sink
        for case in cases
        if case.scenario is not None
    }
    actions = {
        case.scenario.expected_action
        for case in cases
        if case.scenario is not None
    }
    if pair_labels != {False, True}:
        raise ExternalHoldoutError("pair_label_coverage_invalid")
    if reach_labels != {False, True}:
        raise ExternalHoldoutError("scenario_label_coverage_invalid")
    if not {"allow", "block"}.issubset(actions):
        raise ExternalHoldoutError("scenario_action_coverage_invalid")


def _pair_metrics(
    cases: Sequence[dict[str, Any]],
    categories: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "overall": _binary_summary(cases),
        "by_public_category": {
            category: _binary_summary(
                [case for case in cases if case["public_category"] == category]
            )
            for category in categories
        },
        "method_counts": dict(sorted(Counter(case["method"] for case in cases).items())),
    }


def _scenario_metrics(
    cases: Sequence[dict[str, Any]],
    categories: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "overall": _scenario_summary(cases),
        "by_public_category": {
            category: _scenario_summary(
                [case for case in cases if case["public_category"] == category]
            )
            for category in categories
        },
    }


def _parity_metrics(
    cases: Sequence[dict[str, Any]],
    categories: tuple[str, ...],
) -> dict[str, Any]:
    mismatches = sum(not case["passed"] for case in cases)
    return {
        "case_count": len(cases),
        "mismatch_count": mismatches,
        "passed": mismatches == 0,
        "by_public_category": {
            category: {
                "case_count": sum(
                    case["public_category"] == category for case in cases
                ),
                "mismatch_count": sum(
                    case["public_category"] == category and not case["passed"]
                    for case in cases
                ),
            }
            for category in categories
        },
    }


def _binary_summary(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(case["expected"] and case["actual"] for case in cases)
    fp = sum(not case["expected"] and case["actual"] for case in cases)
    tn = sum(not case["expected"] and not case["actual"] for case in cases)
    fn = sum(case["expected"] and not case["actual"] for case in cases)
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
        "f1": f1,
        "accuracy": _safe_ratio(tp + tn, len(cases)),
    }


def _scenario_summary(cases: Sequence[dict[str, Any]]) -> dict[str, Any]:
    reach = [
        {"expected": case["expected_reach"], "actual": case["actual_reach"]}
        for case in cases
    ]
    action_confusion: dict[str, Counter[str]] = defaultdict(Counter)
    action_correct = 0
    false_blocks = 0
    missed_blocks = 0
    for case in cases:
        action_confusion[case["expected_action"]][case["actual_action"]] += 1
        action_correct += case["expected_action"] == case["actual_action"]
        false_blocks += (
            case["expected_action"] == "allow" and case["actual_action"] == "block"
        )
        missed_blocks += (
            case["expected_action"] == "block" and case["actual_action"] != "block"
        )
    return {
        "case_count": len(cases),
        "reachability": _binary_summary(reach),
        "action_accuracy": _safe_ratio(action_correct, len(cases)),
        "action_confusion": {
            expected: dict(sorted(actual.items()))
            for expected, actual in sorted(action_confusion.items())
        },
        "false_blocks": false_blocks,
        "missed_blocks": missed_blocks,
    }


def _quality_assessment(report: dict[str, Any]) -> dict[str, Any]:
    pair = report["metrics"]["pair_classification"]
    e2e = report["metrics"]["end_to_end"]
    parity = report["metrics"]["full_incremental_parity"]
    category_pair_accuracy = min(
        summary["accuracy"] for summary in pair["by_public_category"].values()
    )
    category_e2e_accuracy = min(
        min(summary["reachability"]["accuracy"], summary["action_accuracy"])
        for summary in e2e["by_public_category"].values()
    )
    checks = {
        "pair_precision_is_one": pair["overall"]["precision"] == 1.0,
        "pair_recall_is_one": pair["overall"]["recall"] == 1.0,
        "pair_category_accuracy_is_one": category_pair_accuracy == 1.0,
        "e2e_reachability_f1_is_one": (
            e2e["overall"]["reachability"]["f1"] == 1.0
        ),
        "e2e_action_accuracy_is_one": e2e["overall"]["action_accuracy"] == 1.0,
        "e2e_category_accuracy_is_one": category_e2e_accuracy == 1.0,
        "false_blocks_are_zero": e2e["overall"]["false_blocks"] == 0,
        "missed_blocks_are_zero": e2e["overall"]["missed_blocks"] == 0,
        "full_incremental_parity": parity["passed"],
        "aggregate_report_privacy": report["privacy"]["passed"],
    }
    return {
        "passed": all(checks.values()),
        "checks": dict(sorted(checks.items())),
        "fixed_threshold_profile": "external-holdout-perfect-v1",
    }


def _privacy_audit(
    dataset: ExternalHoldoutDataset,
    report: dict[str, Any],
) -> dict[str, Any]:
    leaves = tuple(_string_leaves(report))
    leaf_set = set(leaves)
    private_values = {
        value for value in dataset.private_texts if len(value) >= _PRIVATE_TEXT_MIN_CHARS
    }
    private_hashes = {
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in dataset.private_texts
    }
    internal_ids = {
        case.pair.example_id
        for case in dataset.cases
        if case.pair is not None
    } | {
        case.scenario.scenario_id
        for case in dataset.cases
        if case.scenario is not None
    }
    forbidden_paths = {
        str(dataset.private_root),
        str(dataset.private_root / EXTERNAL_HOLDOUT_MANIFEST),
        str(dataset.private_root / EXTERNAL_HOLDOUT_CASES),
    }
    counts = {
        "private_text_values": len(private_values & leaf_set),
        "private_text_hashes": len(private_hashes & leaf_set),
        "internal_case_ids": len(internal_ids & leaf_set),
        "private_paths": len(forbidden_paths & leaf_set),
    }
    return {
        "passed": sum(counts.values()) == 0,
        "exposure_counts": counts,
        "surface": "aggregate_only",
    }


def _string_leaves(value: object) -> Sequence[str]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(
            leaf
            for key, item in value.items()
            for leaf in (*_string_leaves(key), *_string_leaves(item))
        )
    if isinstance(value, (list, tuple)):
        return tuple(leaf for item in value for leaf in _string_leaves(item))
    return ()


def _latency_summary(samples_ns: Sequence[int]) -> dict[str, float | int]:
    milliseconds = [sample / 1_000_000 for sample in samples_ns]
    return {
        "samples": len(milliseconds),
        "p50": round(nearest_rank_percentile(milliseconds, 0.50), 6),
        "p95": round(nearest_rank_percentile(milliseconds, 0.95), 6),
        "max": round(max(milliseconds), 6),
    }


def _timed(operation: Callable[[], Any]) -> tuple[Any, int]:
    started = time.perf_counter_ns()
    result = operation()
    return result, time.perf_counter_ns() - started


def _optional_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _safe_ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _metric(value: float | None) -> str:
    return "n/a" if value is None or math.isnan(value) else f"{value:.3f}"
