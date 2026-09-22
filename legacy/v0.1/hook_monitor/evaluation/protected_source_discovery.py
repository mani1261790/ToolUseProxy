from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from hook_monitor.runtime.source_config import CURRENT_MANIFEST_SCHEMA_VERSION


V1_DATASET_SCHEMA_VERSION = 1
V1_DATASET_VERSION = "1.0.0"
V2_DATASET_SCHEMA_VERSION = 2
V2_DATASET_VERSION = "2.0.0"
SUPPORTED_SPLITS = frozenset({"development", "validation"})
SUPPORTED_CATEGORIES = frozenset(
    {
        "supported_positive",
        "supported_negative",
        "out_of_scope_protected",
        "excluded_irrelevant",
    }
)
RUNNER_VERSION = "protected-source-discovery-evaluation-v2"
EXPECTED_V1_DATASET_SHA256 = (
    "ac7f5a24f1fc65a2549392797bcc3177519fbb4f3cbcdb271fd0f3d7cc896ee5"
)
EXPECTED_V2_DATASET_SHA256 = (
    "a4cd72ba5eabb230a8eba2d3a798838f3085398973024eac65c370fca54dc565"
)
_PINNED_DATASET_SHA256 = {
    V1_DATASET_VERSION: EXPECTED_V1_DATASET_SHA256,
    V2_DATASET_VERSION: EXPECTED_V2_DATASET_SHA256,
}

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_PROPOSED_SOURCE_ID_PATTERN = re.compile(
    r"^protected_[a-z0-9_]{1,40}_[a-f0-9]{16}$"
)
_FORBIDDEN_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI-style token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\b"
        ),
    ),
)
_V1_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_version",
        "description",
        "files",
        "expected_counts",
        "go_no_go",
        "baseline",
    }
)
_V2_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_version",
        "description",
        "files",
        "scenario_contract",
        "expected_counts",
        "go_no_go",
        "baselines",
    }
)
_EXPECTED_COUNT_KEYS = frozenset(
    {
        "scenarios",
        "files",
        "development_scenarios",
        "validation_scenarios",
        *SUPPORTED_CATEGORIES,
    }
)
_GO_NO_GO_KEYS = frozenset(
    {
        "minimum_precision",
        "minimum_recall",
        "minimum_selector_precision",
        "minimum_selector_recall",
        "minimum_selector_exact_match_rate",
        "maximum_workspace_candidate_median",
        "maximum_privacy_exposures",
    }
)
_V2_GO_NO_GO_KEYS = _GO_NO_GO_KEYS | {
    "minimum_detected_selector_exact_match_rate",
    "minimum_hard_positive_recall",
    "minimum_negative_family_specificity",
}
_BASELINE_KEYS = frozenset(
    {
        "detector_version",
        "tp",
        "fp",
        "tn",
        "fn",
        "selector_tp",
        "selector_fp",
        "selector_fn",
        "selector_exact_matches",
        "complete_scans",
        "workspace_candidate_median",
        "out_of_scope_candidates",
        "excluded_candidates",
        "privacy_exposures",
    }
)
_V2_BASELINE_KEYS = _BASELINE_KEYS | {
    "detected_selector_exact_matches",
    "detected_positive_files",
    "case_outcomes_sha256",
    "scenario_outcomes_sha256",
}
_SCENARIO_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "provenance",
        "profile",
        "files",
        "tags",
        "rationale",
    }
)
_V1_FILE_KEYS = frozenset(
    {
        "id",
        "path",
        "category",
        "content",
        "expected_selector",
        "canaries",
        "tags",
        "rationale",
    }
)
_V2_FILE_KEYS = _V1_FILE_KEYS | {
    "challenge_family",
    "counterfactual_group",
}
_V2_SCENARIO_CONTRACT_KEYS = frozenset(
    {
        "files_per_scenario",
        "category_counts",
        "challenge_family_counts",
        "hard_positive_families",
        "negative_families",
        "profile_prefixes",
        "split_shape_sha256",
    }
)
_V2_VOCABULARY_KEYS = frozenset(
    {
        "schema_version",
        "dataset_version",
        "normalization",
        "shared_format_tokens",
        "maximum_cross_split_feature_overlap",
        "splits",
    }
)
_V2_VOCABULARY_SPLIT_KEYS = frozenset(
    {
        "pattern_tokens",
        "placeholder_values",
        "protocol_values",
        "path_tokens",
        "canary_prefixes",
    }
)
_PUBLIC_HASH_KEYS = frozenset(
    {
        "source_sha256",
        "content_sha256",
        "source_hash",
        "content_hash",
    }
)


class ProtectedSourceDiscoveryDatasetError(ValueError):
    """Raised when the versioned discovery corpus violates its contract."""


@dataclass(frozen=True)
class DiscoveryFileFixture:
    file_id: str
    relative_path: str
    category: str
    content: str
    expected_selector: dict[str, tuple[str, ...]] | None
    canaries: tuple[str, ...]
    tags: tuple[str, ...]
    rationale: str
    challenge_family: str
    counterfactual_group: str | None

    @property
    def expected_candidate(self) -> bool:
        return self.category == "supported_positive"


@dataclass(frozen=True)
class DiscoveryScenario:
    scenario_id: str
    split: str
    profile: str
    files: tuple[DiscoveryFileFixture, ...]
    tags: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class DiscoveryDataset:
    schema_version: int
    dataset_id: str
    dataset_version: str
    description: str
    digest_sha256: str
    pinned_digest_sha256: str
    expected_counts: dict[str, int]
    go_no_go: dict[str, float]
    baselines: dict[str, dict[str, object]]
    scenarios: tuple[DiscoveryScenario, ...]
    files_per_scenario: int
    category_counts_per_scenario: dict[str, int]
    challenge_family_counts_per_scenario: dict[str, int]
    hard_positive_families: tuple[str, ...]
    negative_families: tuple[str, ...]
    split_vocabulary: dict[str, dict[str, tuple[str, ...]]]
    profile_prefixes: dict[str, str]
    split_shape_sha256: dict[str, str]
    shared_vocabulary_tokens: tuple[str, ...]
    maximum_cross_split_feature_overlap: float
    cross_split_feature_overlap: float

    @property
    def baseline(self) -> dict[str, object]:
        """Backward-compatible access to the complete-corpus baseline."""

        return self.baselines["all"]

    def select_baseline(self, split: str | None) -> dict[str, object]:
        return self.baselines[split or "all"]

    def select_scenarios(
        self,
        split: str | None = None,
    ) -> tuple[DiscoveryScenario, ...]:
        if split is not None and split not in SUPPORTED_SPLITS:
            raise ProtectedSourceDiscoveryDatasetError(
                f"unsupported dataset split: {split}"
            )
        if split is None:
            return self.scenarios
        return tuple(item for item in self.scenarios if item.split == split)


class _ScannerCandidate(Protocol):
    relative_path: str
    detector_version: str
    reason_codes: Sequence[str]
    confidence: float
    proposed_source: Mapping[str, object]


class _ScannerResult(Protocol):
    scanner_version: str
    scan_complete: bool
    truncation_reasons: Sequence[str]
    candidates: Sequence[_ScannerCandidate]
    skipped_counts: Mapping[str, int] | Sequence[tuple[str, int]]


Scanner = Callable[..., _ScannerResult]


def load_protected_source_discovery_dataset(root: Path) -> DiscoveryDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_json_object(manifest_path)
    version = (manifest.get("schema_version"), manifest.get("dataset_version"))
    if version == (V1_DATASET_SCHEMA_VERSION, V1_DATASET_VERSION):
        return _load_v1_dataset(root, manifest_path, manifest)
    if version == (V2_DATASET_SCHEMA_VERSION, V2_DATASET_VERSION):
        return _load_v2_dataset(root, manifest_path, manifest)
    raise ProtectedSourceDiscoveryDatasetError(
        f"{manifest_path}: unsupported discovery dataset version"
    )


def _load_v1_dataset(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> DiscoveryDataset:
    _require_exact_keys(manifest, _V1_MANIFEST_KEYS, manifest_path)

    dataset_id = _require_identifier(
        manifest["dataset_id"], "dataset_id", manifest_path
    )
    description = _require_nonempty_string(
        manifest["description"], "description", manifest_path
    )
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"scenarios"}:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{manifest_path}: files must contain exactly scenarios"
        )
    scenario_path = _resolve_fixture_file(
        root,
        files["scenarios"],
        "files.scenarios",
        manifest_path,
    )
    expected_counts = _parse_expected_counts(
        manifest["expected_counts"], manifest_path
    )
    go_no_go = _parse_go_no_go(manifest["go_no_go"], manifest_path)
    baseline = _parse_baseline(manifest["baseline"], manifest_path)

    records = _load_jsonl(scenario_path)
    scenarios = tuple(
        _parse_scenario(
            record,
            scenario_path,
            line_no,
            schema_version=V1_DATASET_SCHEMA_VERSION,
            dataset_version=V1_DATASET_VERSION,
            files_per_scenario=10,
            file_keys=_V1_FILE_KEYS,
        )
        for line_no, record in records
    )
    category_counts = {
        "supported_positive": 2,
        "supported_negative": 6,
        "out_of_scope_protected": 1,
        "excluded_irrelevant": 1,
    }
    _validate_dataset(
        scenarios,
        expected_counts,
        scenario_path,
        category_counts_per_scenario=category_counts,
        challenge_family_counts_per_scenario={},
        require_disjoint_profiles=False,
    )
    split_counts = _selected_expected_counts(
        tuple(item for item in scenarios if item.split == "development")
    )
    split_baseline = _derive_split_baseline(
        baseline,
        split_counts,
        full_supported_positive_count=expected_counts["supported_positive"],
    )
    digest = _dataset_digest(
        (manifest_path, scenario_path),
        domain=b"tooluseproxy-protected-source-discovery-dataset-v1\0",
    )
    return DiscoveryDataset(
        schema_version=V1_DATASET_SCHEMA_VERSION,
        dataset_id=dataset_id,
        dataset_version=V1_DATASET_VERSION,
        description=description,
        digest_sha256=digest,
        pinned_digest_sha256=_PINNED_DATASET_SHA256[V1_DATASET_VERSION],
        expected_counts=expected_counts,
        go_no_go=go_no_go,
        baselines={
            "all": baseline,
            "development": dict(split_baseline),
            "validation": dict(split_baseline),
        },
        scenarios=scenarios,
        files_per_scenario=10,
        category_counts_per_scenario=category_counts,
        challenge_family_counts_per_scenario={},
        hard_positive_families=(),
        negative_families=(),
        split_vocabulary={},
        profile_prefixes={},
        split_shape_sha256={},
        shared_vocabulary_tokens=(),
        maximum_cross_split_feature_overlap=1.0,
        cross_split_feature_overlap=0.0,
    )


def _load_v2_dataset(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> DiscoveryDataset:
    _require_exact_keys(manifest, _V2_MANIFEST_KEYS, manifest_path)
    dataset_id = _require_identifier(
        manifest["dataset_id"], "dataset_id", manifest_path
    )
    description = _require_nonempty_string(
        manifest["description"], "description", manifest_path
    )
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"scenarios", "vocabulary"}:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{manifest_path}: files must contain exactly scenarios and vocabulary"
        )
    scenario_path = _resolve_fixture_file(
        root, files["scenarios"], "files.scenarios", manifest_path
    )
    vocabulary_path = _resolve_fixture_file(
        root, files["vocabulary"], "files.vocabulary", manifest_path
    )
    (
        files_per_scenario,
        category_counts,
        challenge_family_counts,
        hard_positive_families,
        negative_families,
        profile_prefixes,
        split_shape_sha256,
    ) = _parse_v2_scenario_contract(manifest["scenario_contract"], manifest_path)
    expected_counts = _parse_expected_counts(
        manifest["expected_counts"], manifest_path
    )
    go_no_go = _parse_go_no_go(
        manifest["go_no_go"], manifest_path, keys=_V2_GO_NO_GO_KEYS
    )
    baselines = _parse_v2_baselines(manifest["baselines"], manifest_path)
    vocabulary, shared_vocabulary_tokens, maximum_feature_overlap = _parse_v2_vocabulary(
        _load_json_object(vocabulary_path), vocabulary_path
    )
    records = _load_jsonl(scenario_path)
    scenarios = tuple(
        _parse_scenario(
            record,
            scenario_path,
            line_no,
            schema_version=V2_DATASET_SCHEMA_VERSION,
            dataset_version=V2_DATASET_VERSION,
            files_per_scenario=files_per_scenario,
            file_keys=_V2_FILE_KEYS,
        )
        for line_no, record in records
    )
    _validate_dataset(
        scenarios,
        expected_counts,
        scenario_path,
        category_counts_per_scenario=category_counts,
        challenge_family_counts_per_scenario=challenge_family_counts,
        require_disjoint_profiles=True,
    )
    cross_split_feature_overlap = _validate_v2_vocabulary(
        scenarios,
        vocabulary,
        shared_vocabulary_tokens=shared_vocabulary_tokens,
        maximum_feature_overlap=maximum_feature_overlap,
        location=vocabulary_path,
    )
    _validate_counterfactual_groups(scenarios, scenario_path)
    _validate_v2_shape_contract(
        scenarios,
        profile_prefixes=profile_prefixes,
        expected_shape_sha256=split_shape_sha256,
        location=scenario_path,
    )
    digest = _dataset_digest(
        (manifest_path, scenario_path, vocabulary_path),
        domain=b"tooluseproxy-protected-source-discovery-dataset-v2\0",
    )
    return DiscoveryDataset(
        schema_version=V2_DATASET_SCHEMA_VERSION,
        dataset_id=dataset_id,
        dataset_version=V2_DATASET_VERSION,
        description=description,
        digest_sha256=digest,
        pinned_digest_sha256=_PINNED_DATASET_SHA256[V2_DATASET_VERSION],
        expected_counts=expected_counts,
        go_no_go=go_no_go,
        baselines=baselines,
        scenarios=scenarios,
        files_per_scenario=files_per_scenario,
        category_counts_per_scenario=category_counts,
        challenge_family_counts_per_scenario=challenge_family_counts,
        hard_positive_families=hard_positive_families,
        negative_families=negative_families,
        split_vocabulary=vocabulary,
        profile_prefixes=profile_prefixes,
        split_shape_sha256=split_shape_sha256,
        shared_vocabulary_tokens=shared_vocabulary_tokens,
        maximum_cross_split_feature_overlap=maximum_feature_overlap,
        cross_split_feature_overlap=cross_split_feature_overlap,
    )


def evaluate_protected_source_discovery(
    dataset: DiscoveryDataset,
    *,
    split: str | None = None,
    scanner: Scanner | None = None,
) -> dict[str, Any]:
    scenarios = dataset.select_scenarios(split)
    if not scenarios:
        raise ValueError("selected discovery dataset split has no scenarios")
    scanner_callable = scanner or _default_scanner

    file_cases: list[dict[str, Any]] = []
    scenario_cases: list[dict[str, Any]] = []
    candidate_counts: list[int] = []
    scanner_versions: set[str] = set()
    detector_versions: set[str] = set()
    aggregate_skips: Counter[str] = Counter()
    candidate_surface_exposures = 0
    candidate_selected_scalar_exposures = 0
    candidate_selected_scalar_fingerprint_exposures = 0
    candidate_absolute_path_exposures = 0
    candidate_hash_field_exposures = 0
    duplicate_candidate_count = 0
    unknown_candidate_count = 0
    invalid_candidate_public_contract_count = 0
    invalid_selector_candidate_count = 0
    scanner_error_count = 0
    out_of_scope_candidates = 0
    excluded_candidates = 0

    with tempfile.TemporaryDirectory(prefix="tooluseproxy-discovery-eval-") as temporary:
        evaluation_root = Path(temporary)
        for scenario in scenarios:
            workspace = evaluation_root / scenario.scenario_id
            _materialize_scenario(workspace, scenario)
            known_by_path = {
                fixture.relative_path: fixture for fixture in scenario.files
            }
            expected_protected_scalars = _expected_protected_scalars(scenario.files)
            candidates_by_path: dict[str, list[_ScannerCandidate]] = defaultdict(list)
            scan_complete = False
            truncation_reasons: tuple[str, ...] = ()
            scanner_error_type: str | None = None
            skipped_counts: dict[str, int] = {}
            try:
                result = scanner_callable(
                    workspace,
                    workspace_id=f"discovery-eval-{scenario.scenario_id}",
                )
                scanner_versions.add(str(result.scanner_version))
                scan_complete = bool(result.scan_complete)
                truncation_reasons = tuple(sorted(map(str, result.truncation_reasons)))
                raw_skipped_counts = result.skipped_counts
                skipped_items = (
                    raw_skipped_counts.items()
                    if isinstance(raw_skipped_counts, Mapping)
                    else raw_skipped_counts
                )
                skipped_counts = {
                    str(key): int(value)
                    for key, value in sorted(skipped_items)
                }
                aggregate_skips.update(skipped_counts)
                for candidate in result.candidates:
                    path = str(candidate.relative_path)
                    candidates_by_path[path].append(candidate)
                    detector_versions.add(str(candidate.detector_version))
                    invalid_candidate_public_contract_count += int(
                        not _candidate_public_contract_valid(candidate)
                    )
                    surface = _candidate_public_surface(candidate)
                    encoded_surface = json.dumps(
                        surface,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    candidate_surface_exposures += _count_canary_exposures(
                        encoded_surface,
                        scenario.files,
                    )
                    candidate_selected_scalar_exposures += (
                        _count_selected_scalar_leaf_exposures(
                            surface, expected_protected_scalars
                        )
                    )
                    candidate_selected_scalar_fingerprint_exposures += (
                        _count_selected_scalar_fingerprint_leaf_exposures(
                            surface, expected_protected_scalars
                        )
                    )
                    candidate_absolute_path_exposures += int(
                        str(workspace.resolve()) in encoded_surface
                    )
                    candidate_hash_field_exposures += _count_forbidden_hash_keys(
                        surface
                    )
            except Exception as error:  # evaluator must not serialize exception text
                scanner_error_count += 1
                scanner_error_type = type(error).__name__

            candidate_count = sum(len(items) for items in candidates_by_path.values())
            candidate_counts.append(candidate_count)
            duplicate_candidate_count += sum(
                max(0, len(items) - 1) for items in candidates_by_path.values()
            )
            unknown_candidate_count += sum(
                len(items)
                for path, items in candidates_by_path.items()
                if path not in known_by_path
            )

            for fixture in scenario.files:
                path_candidates = candidates_by_path.get(fixture.relative_path, [])
                actual_candidate = bool(path_candidates)
                actual_selector: dict[str, tuple[str, ...]] | None = None
                if path_candidates:
                    actual_selector = _candidate_selector(path_candidates[0])
                    if actual_selector is None:
                        invalid_selector_candidate_count += 1
                selector_exact = (
                    actual_selector == fixture.expected_selector
                    if fixture.expected_candidate
                    else actual_selector is None
                )
                if fixture.category == "out_of_scope_protected" and actual_candidate:
                    out_of_scope_candidates += 1
                if fixture.category == "excluded_irrelevant" and actual_candidate:
                    excluded_candidates += 1
                file_cases.append(
                    {
                        "id": fixture.file_id,
                        "scenario_id": scenario.scenario_id,
                        "split": scenario.split,
                        "relative_path": fixture.relative_path,
                        "category": fixture.category,
                        "challenge_family": fixture.challenge_family,
                        "counterfactual_group": fixture.counterfactual_group,
                        "tags": list(fixture.tags),
                        "expected_candidate": fixture.expected_candidate,
                        "actual_candidate": actual_candidate,
                        "actual_selector": (
                            None
                            if actual_selector is None
                            else {
                                kind: list(values)
                                for kind, values in actual_selector.items()
                            }
                        ),
                        "selector_exact": selector_exact,
                    }
                )

            scenario_cases.append(
                {
                    "id": scenario.scenario_id,
                    "split": scenario.split,
                    "profile": scenario.profile,
                    "scan_complete": scan_complete,
                    "truncation_reasons": list(truncation_reasons),
                    "candidate_count": candidate_count,
                    "skipped_counts": skipped_counts,
                    "scanner_error_type": scanner_error_type,
                }
            )

    supported_cases = [
        case
        for case in file_cases
        if case["category"] in {"supported_positive", "supported_negative"}
    ]
    classification = _classification_metrics(supported_cases)
    selector_metrics = _selector_metrics(file_cases, scenarios)
    by_tag = _by_tag_metrics(supported_cases)
    by_challenge_family = _by_challenge_family_metrics(file_cases)
    hard_positive_recall = _hard_positive_recall(
        supported_cases, dataset.hard_positive_families
    )
    negative_family_specificity = _negative_family_specificity(
        supported_cases, dataset.negative_families
    )
    counterfactual_metrics = _counterfactual_metrics(file_cases)
    complete_scans = sum(bool(case["scan_complete"]) for case in scenario_cases)
    workspace_candidate_median = float(statistics.median(candidate_counts))
    case_outcomes_sha256 = _case_outcomes_digest(file_cases)
    scenario_outcomes_sha256 = _scenario_outcomes_digest(scenario_cases)

    selected_expected_counts = _selected_expected_counts(scenarios)
    deterministic_metrics = {
        "tp": classification["tp"],
        "fp": classification["fp"],
        "tn": classification["tn"],
        "fn": classification["fn"],
        "selector_tp": selector_metrics["tp"],
        "selector_fp": selector_metrics["fp"],
        "selector_fn": selector_metrics["fn"],
        "selector_exact_matches": selector_metrics["exact_matches"],
        "detected_selector_exact_matches": selector_metrics[
            "detected_exact_matches"
        ],
        "detected_positive_files": selector_metrics["detected_positive_files"],
        "complete_scans": complete_scans,
        "workspace_candidate_median": workspace_candidate_median,
        "out_of_scope_candidates": out_of_scope_candidates,
        "excluded_candidates": excluded_candidates,
        "privacy_exposures": (
            candidate_surface_exposures
            + candidate_selected_scalar_exposures
            + candidate_selected_scalar_fingerprint_exposures
            + candidate_absolute_path_exposures
            + candidate_hash_field_exposures
        ),
        "case_outcomes_sha256": case_outcomes_sha256,
        "scenario_outcomes_sha256": scenario_outcomes_sha256,
    }
    baseline_expected = dataset.select_baseline(split)
    baseline_reproduced = _baseline_matches(
        baseline_expected,
        deterministic_metrics,
        detector_versions,
    )

    scope_total = (
        selected_expected_counts["supported_positive"]
        + selected_expected_counts["out_of_scope_protected"]
    )
    scope_coverage = _ratio(
        selected_expected_counts["supported_positive"], scope_total
    )
    go_no_go = _go_no_go_assessment(
        dataset.go_no_go,
        classification=classification,
        selector_metrics=selector_metrics,
        hard_positive_recall=hard_positive_recall,
        minimum_negative_family_specificity=negative_family_specificity[
            "minimum_specificity"
        ],
        workspace_candidate_median=workspace_candidate_median,
        privacy_exposures=deterministic_metrics["privacy_exposures"],
    )
    runtime_invariants = {
        "all_scans_complete": complete_scans == len(scenarios),
        "no_scanner_errors": scanner_error_count == 0,
        "no_duplicate_candidates": duplicate_candidate_count == 0,
        "no_unknown_candidates": unknown_candidate_count == 0,
        "no_invalid_candidate_public_contracts": (
            invalid_candidate_public_contract_count == 0
        ),
        "no_invalid_candidate_selectors": invalid_selector_candidate_count == 0,
        "no_out_of_scope_candidates": out_of_scope_candidates == 0,
        "no_excluded_candidates": excluded_candidates == 0,
    }
    invariants_passed = all(runtime_invariants.values())

    report: dict[str, Any] = {
        "schema_version": 2,
        "runner_version": RUNNER_VERSION,
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "sha256": dataset.digest_sha256,
            "digest_matches_pinned": (
                dataset.digest_sha256 == dataset.pinned_digest_sha256
            ),
            "cross_split_feature_overlap": dataset.cross_split_feature_overlap,
            "maximum_cross_split_feature_overlap": (
                dataset.maximum_cross_split_feature_overlap
            ),
            "split_shape_sha256": dict(sorted(dataset.split_shape_sha256.items())),
            "split": split or "all",
            **selected_expected_counts,
        },
        "scanner": {
            "versions": sorted(scanner_versions),
            "detector_versions": sorted(detector_versions),
            "scan_complete_count": complete_scans,
            "scan_incomplete_count": len(scenarios) - complete_scans,
            "workspace_candidate_median": workspace_candidate_median,
            "duplicate_candidate_count": duplicate_candidate_count,
            "unknown_candidate_count": unknown_candidate_count,
            "invalid_candidate_public_contract_count": (
                invalid_candidate_public_contract_count
            ),
            "invalid_selector_candidate_count": invalid_selector_candidate_count,
            "scanner_error_count": scanner_error_count,
            "skipped_counts": dict(sorted(aggregate_skips.items())),
        },
        "metrics": {
            "file_classification": classification,
            "selector_classification": selector_metrics,
            "by_tag": by_tag,
            "by_challenge_family": by_challenge_family,
            "hard_positive_recall": hard_positive_recall,
            "negative_family_specificity": negative_family_specificity,
            "counterfactual": counterfactual_metrics,
            "scope_coverage": {
                "supported_protected_files": selected_expected_counts[
                    "supported_positive"
                ],
                "out_of_scope_protected_files": selected_expected_counts[
                    "out_of_scope_protected"
                ],
                "supported_fraction": scope_coverage,
                "out_of_scope_candidate_count": out_of_scope_candidates,
                "excluded_candidate_count": excluded_candidates,
            },
            "privacy": {
                "candidate_public_canary_exposure_count": (
                    candidate_surface_exposures
                ),
                "candidate_selected_scalar_leaf_exposure_count": (
                    candidate_selected_scalar_exposures
                ),
                "candidate_selected_scalar_fingerprint_leaf_exposure_count": (
                    candidate_selected_scalar_fingerprint_exposures
                ),
                "candidate_absolute_workspace_path_exposure_count": (
                    candidate_absolute_path_exposures
                ),
                "candidate_public_hash_field_exposure_count": (
                    candidate_hash_field_exposures
                ),
                "report_canary_exposure_count": 0,
                "report_selected_scalar_leaf_exposure_count": 0,
                "report_selected_scalar_fingerprint_leaf_exposure_count": 0,
                "total_exposure_count": deterministic_metrics[
                    "privacy_exposures"
                ],
            },
        },
        "baseline": {
            "expected": baseline_expected,
            "observed": deterministic_metrics,
            "reproduced": baseline_reproduced,
        },
        "go_no_go": go_no_go,
        "invariants": {
            **runtime_invariants,
            "passed": invariants_passed,
        },
        "summary": {
            "status": "go" if go_no_go["passed"] else "no_go",
            "go_no_go_passed": go_no_go["passed"],
            "baseline_reproduced": baseline_reproduced,
            "privacy_passed": deterministic_metrics["privacy_exposures"] == 0,
            "invariants_passed": invariants_passed,
            "check_passed": False,
        },
        "cases": {
            "scenarios": scenario_cases,
            "files": file_cases,
        },
    }
    report_canary_exposures = _count_report_canary_exposures(report, scenarios)
    report["metrics"]["privacy"][
        "report_canary_exposure_count"
    ] = report_canary_exposures
    report_selected_scalar_exposures = _count_report_selected_scalar_exposures(
        report, scenarios
    )
    report["metrics"]["privacy"][
        "report_selected_scalar_leaf_exposure_count"
    ] = report_selected_scalar_exposures
    report_selected_scalar_fingerprint_exposures = (
        _count_report_selected_scalar_fingerprint_exposures(report, scenarios)
    )
    report["metrics"]["privacy"][
        "report_selected_scalar_fingerprint_leaf_exposure_count"
    ] = report_selected_scalar_fingerprint_exposures
    final_report_exposures = (
        report_canary_exposures
        + report_selected_scalar_exposures
        + report_selected_scalar_fingerprint_exposures
    )
    report["metrics"]["privacy"]["total_exposure_count"] += final_report_exposures
    report["baseline"]["observed"]["privacy_exposures"] += final_report_exposures
    privacy_passed = report["metrics"]["privacy"]["total_exposure_count"] == 0
    report["baseline"]["reproduced"] = _baseline_matches(
        baseline_expected,
        report["baseline"]["observed"],
        detector_versions,
    )
    report["go_no_go"]["checks"]["privacy"] = privacy_passed
    report["go_no_go"]["passed"] = all(report["go_no_go"]["checks"].values())
    report["summary"]["status"] = (
        "go" if report["go_no_go"]["passed"] else "no_go"
    )
    report["summary"]["go_no_go_passed"] = report["go_no_go"]["passed"]
    report["summary"]["baseline_reproduced"] = report["baseline"]["reproduced"]
    report["summary"]["privacy_passed"] = privacy_passed
    report["summary"]["check_passed"] = bool(
        report["dataset"]["digest_matches_pinned"]
        and report["baseline"]["reproduced"]
        and privacy_passed
        and invariants_passed
    )
    return report


def render_protected_source_discovery_report(report: Mapping[str, Any]) -> str:
    dataset = report["dataset"]
    files = report["metrics"]["file_classification"]
    selectors = report["metrics"]["selector_classification"]
    scanner = report["scanner"]
    privacy = report["metrics"]["privacy"]
    scope = report["metrics"]["scope_coverage"]
    hard_positive_recall = report["metrics"]["hard_positive_recall"]
    negative_specificity = report["metrics"]["negative_family_specificity"]
    summary = report["summary"]
    lines = [
        (
            f"protected-source discovery dataset={dataset['id']} "
            f"version={dataset['version']} split={dataset['split']} "
            f"sha256={str(dataset['sha256'])[:12]}"
        ),
        (
            f"workspaces={dataset['scenarios']} files={dataset['files']} "
            f"supported_positive={dataset['supported_positive']} "
            f"supported_negative={dataset['supported_negative']}"
        ),
        (
            "file gate "
            f"precision={_format_ratio(files['precision'])} "
            f"recall={_format_ratio(files['recall'])} "
            f"f1={_format_ratio(files['f1'])} "
            f"tp={files['tp']} fp={files['fp']} "
            f"tn={files['tn']} fn={files['fn']}"
        ),
        (
            "selector gate "
            f"precision={_format_ratio(selectors['precision'])} "
            f"recall={_format_ratio(selectors['recall'])} "
            f"exact={_format_ratio(selectors['exact_match_rate'])} "
            "detected_exact="
            f"{_format_ratio(selectors['detected_exact_match_rate'])} "
            f"tp={selectors['tp']} fp={selectors['fp']} fn={selectors['fn']}"
        ),
        (
            f"scan complete={scanner['scan_complete_count']}/{dataset['scenarios']} "
            f"candidate_median={scanner['workspace_candidate_median']:.1f} "
            f"duplicates={scanner['duplicate_candidate_count']} "
            f"errors={scanner['scanner_error_count']}"
        ),
        (
            "family gate "
            f"hard_positive_recall={_format_ratio(hard_positive_recall)} "
            "minimum_negative_specificity="
            f"{_format_ratio(negative_specificity['minimum_specificity'])}"
        ),
        (
            "scope "
            f"supported_fraction={_format_ratio(scope['supported_fraction'])} "
            f"out_of_scope={scope['out_of_scope_protected_files']} "
            f"unexpected_out_of_scope_candidates="
            f"{scope['out_of_scope_candidate_count']}"
        ),
        (
            f"privacy exposures={privacy['total_exposure_count']} "
            f"baseline={'PASS' if summary['baseline_reproduced'] else 'FAIL'} "
            f"invariants={'PASS' if summary['invariants_passed'] else 'FAIL'}"
        ),
        (
            f"go/no-go={'GO' if summary['go_no_go_passed'] else 'NO-GO'} "
            f"check={'PASS' if summary['check_passed'] else 'FAIL'}"
        ),
    ]
    if files["false_positive_ids"]:
        lines.append(
            "file false positives: "
            + _format_bounded_ids(files["false_positive_ids"])
        )
    if files["false_negative_ids"]:
        lines.append(
            "file false negatives: "
            + _format_bounded_ids(files["false_negative_ids"])
        )
    return "\n".join(lines)


def _default_scanner(workspace: Path, *, workspace_id: str) -> _ScannerResult:
    from tooluseproxy.protected_sources import scan_protected_sources

    return scan_protected_sources(workspace, workspace_id=workspace_id)


def _materialize_scenario(workspace: Path, scenario: DiscoveryScenario) -> None:
    workspace.mkdir(mode=0o700)
    for fixture in scenario.files:
        path = workspace.joinpath(*PurePosixPath(fixture.relative_path).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(fixture.content, encoding="utf-8")
        path.chmod(0o600)
    manifest_path = workspace / "protected_sources.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
                "sources": [],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)


def _candidate_public_surface(candidate: _ScannerCandidate) -> dict[str, object]:
    return {
        "path": str(candidate.relative_path),
        "reason_codes": list(candidate.reason_codes),
        "confidence": float(candidate.confidence),
        "proposed_source": _json_safe_copy(candidate.proposed_source),
    }


def _candidate_public_contract_valid(candidate: _ScannerCandidate) -> bool:
    proposed = candidate.proposed_source
    relative_path = str(candidate.relative_path)
    expected_reason_codes = (
        ("secret_like_json_key",)
        if relative_path.casefold().endswith(".json")
        else ("secret_like_dotenv_key",)
    )
    if not isinstance(proposed, Mapping) or set(proposed) != {
        "id",
        "path",
        "type",
        "sensitivity",
        "policy_tags",
        "selector",
    }:
        return False
    source_id = proposed.get("id")
    return (
        isinstance(source_id, str)
        and _PROPOSED_SOURCE_ID_PATTERN.fullmatch(source_id) is not None
        and proposed.get("path") == relative_path
        and proposed.get("type") == "secretfile"
        and proposed.get("sensitivity") == "high"
        and proposed.get("policy_tags") == ["no_external", "no_search"]
        and _candidate_selector(candidate) is not None
        and tuple(candidate.reason_codes) == expected_reason_codes
        and type(candidate.confidence) in {int, float}
        and float(candidate.confidence) == 0.95
    )


def _candidate_selector(
    candidate: _ScannerCandidate,
) -> dict[str, tuple[str, ...]] | None:
    proposed = candidate.proposed_source
    if not isinstance(proposed, Mapping):
        return None
    selector = proposed.get("selector")
    if not isinstance(selector, Mapping) or len(selector) != 1:
        return None
    kind = next(iter(selector))
    values = selector.get(kind)
    if (
        kind not in {"dotenv_keys", "json_pointers"}
        or not isinstance(values, Sequence)
        or isinstance(values, (str, bytes))
        or not values
        or not all(isinstance(value, str) and value for value in values)
    ):
        return None
    return {str(kind): tuple(map(str, values))}


def _classification_metrics(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    tp_ids: list[str] = []
    fp_ids: list[str] = []
    tn_ids: list[str] = []
    fn_ids: list[str] = []
    for case in cases:
        expected = bool(case["expected_candidate"])
        actual = bool(case["actual_candidate"])
        target = (
            tp_ids
            if expected and actual
            else fp_ids
            if actual
            else fn_ids
            if expected
            else tn_ids
        )
        target.append(str(case["id"]))
    tp, fp, tn, fn = map(len, (tp_ids, fp_ids, tn_ids, fn_ids))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "case_count": len(cases),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "effective_recall": recall,
        "f1": _f1(precision, recall),
        "true_positive_ids": sorted(tp_ids),
        "false_positive_ids": sorted(fp_ids),
        "true_negative_ids": sorted(tn_ids),
        "false_negative_ids": sorted(fn_ids),
    }


def _selector_metrics(
    file_cases: Sequence[Mapping[str, Any]],
    scenarios: Sequence[DiscoveryScenario],
) -> dict[str, Any]:
    fixtures = {
        fixture.file_id: fixture
        for scenario in scenarios
        for fixture in scenario.files
    }
    expected_items: set[tuple[str, str, str]] = set()
    actual_items: set[tuple[str, str, str]] = set()
    exact_matches = 0
    expected_files = 0
    detected_positive_files = 0
    detected_exact_matches = 0
    for case in file_cases:
        fixture = fixtures[str(case["id"])]
        if fixture.expected_selector is not None:
            expected_files += 1
            if bool(case["selector_exact"]):
                exact_matches += 1
            if bool(case["actual_candidate"]):
                detected_positive_files += 1
                if bool(case["selector_exact"]):
                    detected_exact_matches += 1
            for kind, values in fixture.expected_selector.items():
                expected_items.update(
                    (fixture.file_id, kind, value) for value in values
                )
        raw_actual_selector = case["actual_selector"]
        if isinstance(raw_actual_selector, Mapping):
            for kind, values in raw_actual_selector.items():
                if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                    actual_items.update(
                        (fixture.file_id, str(kind), str(value))
                        for value in values
                    )
    tp = len(expected_items & actual_items)
    fp = len(actual_items - expected_items)
    fn = len(expected_items - actual_items)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "expected_item_count": len(expected_items),
        "actual_item_count": len(actual_items),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "expected_file_count": expected_files,
        "exact_matches": exact_matches,
        "exact_match_rate": _ratio(exact_matches, expected_files),
        "detected_positive_files": detected_positive_files,
        "detected_exact_matches": detected_exact_matches,
        "detected_exact_match_rate": _ratio(
            detected_exact_matches, detected_positive_files
        ),
    }


def _by_tag_metrics(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    tags = sorted({tag for case in cases for tag in case["tags"]})
    return {
        tag: _compact_classification(
            _classification_metrics(
                [case for case in cases if tag in case["tags"]]
            )
        )
        for tag in tags
    }


def _by_challenge_family_metrics(
    cases: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    families = sorted({str(case["challenge_family"]) for case in cases})
    return {
        family: _compact_classification(
            _classification_metrics(
                [case for case in cases if case["challenge_family"] == family]
            )
        )
        for family in families
    }


def _hard_positive_recall(
    cases: Sequence[Mapping[str, Any]],
    families: Sequence[str],
) -> float:
    selected = [
        case
        for case in cases
        if case["category"] == "supported_positive"
        and (not families or case["challenge_family"] in families)
    ]
    return _classification_metrics(selected)["recall"] if selected else 0.0


def _negative_family_specificity(
    cases: Sequence[Mapping[str, Any]],
    families: Sequence[str],
) -> dict[str, Any]:
    selected_families = tuple(families) or tuple(
        sorted(
            {
                str(case["challenge_family"])
                for case in cases
                if case["category"] == "supported_negative"
            }
        )
    )
    by_family: dict[str, float] = {}
    for family in selected_families:
        family_cases = [
            case
            for case in cases
            if case["category"] == "supported_negative"
            and case["challenge_family"] == family
        ]
        if family_cases:
            true_negatives = sum(
                not bool(case["actual_candidate"]) for case in family_cases
            )
            by_family[family] = _ratio(true_negatives, len(family_cases))
    return {
        "by_family": dict(sorted(by_family.items())),
        "minimum_specificity": min(by_family.values(), default=0.0),
    }


def _counterfactual_metrics(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for case in cases:
        group = case.get("counterfactual_group")
        if isinstance(group, str):
            grouped[group].append(case)
    passed_ids: list[str] = []
    failed_ids: list[str] = []
    for group, group_cases in sorted(grouped.items()):
        passed = all(
            bool(case["actual_candidate"]) == bool(case["expected_candidate"])
            and (
                not bool(case["expected_candidate"])
                or bool(case["selector_exact"])
            )
            for case in group_cases
        )
        (passed_ids if passed else failed_ids).append(group)
    return {
        "group_count": len(grouped),
        "passed": len(passed_ids),
        "failed": len(failed_ids),
        "accuracy": _ratio(len(passed_ids), len(grouped)),
        "failed_ids": failed_ids,
    }


def _compact_classification(metrics: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: metrics[key]
        for key in (
            "case_count",
            "tp",
            "fp",
            "tn",
            "fn",
            "precision",
            "recall",
            "f1",
            "false_positive_ids",
            "false_negative_ids",
        )
    }


def _go_no_go_assessment(
    thresholds: Mapping[str, float],
    *,
    classification: Mapping[str, Any],
    selector_metrics: Mapping[str, Any],
    hard_positive_recall: float,
    minimum_negative_family_specificity: float,
    workspace_candidate_median: float,
    privacy_exposures: object,
) -> dict[str, Any]:
    checks = {
        "precision": float(classification["precision"])
        >= thresholds["minimum_precision"],
        "recall": float(classification["recall"])
        >= thresholds["minimum_recall"],
        "selector_precision": float(selector_metrics["precision"])
        >= thresholds["minimum_selector_precision"],
        "selector_recall": float(selector_metrics["recall"])
        >= thresholds["minimum_selector_recall"],
        "selector_exact_match": float(selector_metrics["exact_match_rate"])
        >= thresholds["minimum_selector_exact_match_rate"],
        "workspace_candidate_median": workspace_candidate_median
        <= thresholds["maximum_workspace_candidate_median"],
        "privacy": int(privacy_exposures)
        <= int(thresholds["maximum_privacy_exposures"]),
    }
    if "minimum_detected_selector_exact_match_rate" in thresholds:
        checks["detected_selector_exact_match"] = (
            float(selector_metrics["detected_exact_match_rate"])
            >= thresholds["minimum_detected_selector_exact_match_rate"]
        )
    if "minimum_hard_positive_recall" in thresholds:
        checks["hard_positive_recall"] = (
            hard_positive_recall >= thresholds["minimum_hard_positive_recall"]
        )
    if "minimum_negative_family_specificity" in thresholds:
        checks["negative_family_specificity"] = (
            minimum_negative_family_specificity
            >= thresholds["minimum_negative_family_specificity"]
        )
    return {
        "thresholds": dict(sorted(thresholds.items())),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _selected_expected_counts(
    scenarios: Sequence[DiscoveryScenario],
) -> dict[str, int]:
    category_counts = Counter(
        fixture.category for scenario in scenarios for fixture in scenario.files
    )
    return {
        "scenarios": len(scenarios),
        "files": sum(len(scenario.files) for scenario in scenarios),
        **{category: category_counts[category] for category in sorted(SUPPORTED_CATEGORIES)},
    }


def _derive_split_baseline(
    baseline: Mapping[str, object],
    counts: Mapping[str, int],
    *,
    full_supported_positive_count: int,
) -> dict[str, object]:
    ratio = counts["supported_positive"] / full_supported_positive_count
    integer_fields = {
        "tp",
        "fp",
        "tn",
        "fn",
        "selector_tp",
        "selector_fp",
        "selector_fn",
        "selector_exact_matches",
        "complete_scans",
        "out_of_scope_candidates",
        "excluded_candidates",
        "privacy_exposures",
    }
    result: dict[str, object] = {}
    for key, value in baseline.items():
        if key in integer_fields:
            result[key] = int(int(value) * ratio)
        else:
            result[key] = value
    return result


def _baseline_matches(
    expected: Mapping[str, object],
    observed: Mapping[str, object],
    detector_versions: set[str],
) -> bool:
    expected_version = expected.get("detector_version")
    if detector_versions != {expected_version}:
        return False
    return all(
        observed.get(key) == value
        for key, value in expected.items()
        if key != "detector_version"
    )


def _case_outcomes_digest(cases: Sequence[Mapping[str, Any]]) -> str:
    payload = [
        {
            "id": str(case["id"]),
            "actual_candidate": bool(case["actual_candidate"]),
            "actual_selector": case["actual_selector"],
            "selector_exact": bool(case["selector_exact"]),
        }
        for case in sorted(cases, key=lambda item: str(item["id"]))
    ]
    return _outcomes_digest(
        b"tooluseproxy-protected-source-discovery-case-outcomes-v1\0",
        payload,
    )


def _scenario_outcomes_digest(cases: Sequence[Mapping[str, Any]]) -> str:
    payload = [
        {
            "id": str(case["id"]),
            "scan_complete": bool(case["scan_complete"]),
            "truncation_reasons": list(case["truncation_reasons"]),
            "candidate_count": int(case["candidate_count"]),
            "skipped_counts": dict(case["skipped_counts"]),
            "scanner_error_type": case["scanner_error_type"],
        }
        for case in sorted(cases, key=lambda item: str(item["id"]))
    ]
    return _outcomes_digest(
        b"tooluseproxy-protected-source-discovery-scenario-outcomes-v1\0",
        payload,
    )


def _outcomes_digest(domain: bytes, payload: object) -> str:
    digest = hashlib.sha256(domain)
    digest.update(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return digest.hexdigest()


def _count_report_canary_exposures(
    report: Mapping[str, Any],
    scenarios: Sequence[DiscoveryScenario],
) -> int:
    serialized = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sum(
        serialized.count(canary)
        for scenario in scenarios
        for fixture in scenario.files
        for canary in fixture.canaries
    )


def _count_canary_exposures(
    serialized: str,
    fixtures: Sequence[DiscoveryFileFixture],
) -> int:
    return sum(
        serialized.count(canary)
        for fixture in fixtures
        for canary in fixture.canaries
    )


def _expected_protected_scalars(
    fixtures: Sequence[DiscoveryFileFixture],
) -> frozenset[str]:
    values: set[str] = set()
    for fixture in fixtures:
        selector = fixture.expected_selector
        if selector is None:
            continue
        if "dotenv_keys" in selector:
            assignments = _fixture_dotenv_assignments(fixture.content)
            values.update(
                value
                for key in selector["dotenv_keys"]
                if (value := assignments.get(key))
            )
        elif "json_pointers" in selector:
            try:
                payload = json.loads(fixture.content)
            except (json.JSONDecodeError, RecursionError):
                continue
            for pointer in selector["json_pointers"]:
                selected = _resolve_fixture_json_pointer(payload, pointer)
                if isinstance(selected, str) and selected:
                    values.add(selected)
    return frozenset(values)


def _fixture_dotenv_assignments(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?:export\s+)?([^=\s]+)\s*=\s*(.*)$", line)
        if match is None:
            continue
        raw_value = match.group(2).strip()
        if (
            len(raw_value) >= 2
            and raw_value[0] in {"'", '"'}
            and raw_value[-1] == raw_value[0]
        ):
            value = raw_value[1:-1]
        else:
            value = raw_value.split(" #", 1)[0].rstrip()
        result[match.group(1)] = value
    return result


def _resolve_fixture_json_pointer(payload: object, pointer: str) -> object:
    current = payload
    if not pointer.startswith("/"):
        return None
    for raw_segment in pointer[1:].split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _count_selected_scalar_leaf_exposures(
    value: object,
    expected_scalars: frozenset[str],
) -> int:
    return sum(
        scalar in leaf
        for leaf in _string_value_leaves(value)
        for scalar in expected_scalars
    )


def _count_selected_scalar_fingerprint_leaf_exposures(
    value: object,
    expected_scalars: frozenset[str],
) -> int:
    expected_sha256 = {
        hashlib.sha256(scalar.encode("utf-8")).hexdigest()
        for scalar in expected_scalars
    }
    return sum(
        fingerprint in leaf.casefold()
        for leaf in _string_value_leaves(value)
        for fingerprint in expected_sha256
    )


def _count_report_selected_scalar_exposures(
    report: Mapping[str, Any],
    scenarios: Sequence[DiscoveryScenario],
) -> int:
    expected = _expected_protected_scalars(
        tuple(
            fixture
            for scenario in scenarios
            for fixture in scenario.files
        )
    )
    return _count_selected_scalar_leaf_exposures(report, expected)


def _count_report_selected_scalar_fingerprint_exposures(
    report: Mapping[str, Any],
    scenarios: Sequence[DiscoveryScenario],
) -> int:
    expected = _expected_protected_scalars(
        tuple(
            fixture
            for scenario in scenarios
            for fixture in scenario.files
        )
    )
    return _count_selected_scalar_fingerprint_leaf_exposures(report, expected)


def _string_value_leaves(value: object) -> Iterator[str]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            stack.extend(current)


def _count_forbidden_hash_keys(value: object) -> int:
    count = 0
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            count += sum(str(key) in _PUBLIC_HASH_KEYS for key in current)
            stack.extend(current.values())
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            stack.extend(current)
    return count


def _json_safe_copy(value: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        decoded = json.loads(encoded)
    except (TypeError, ValueError):
        return {"invalid": True}
    return decoded if isinstance(decoded, dict) else {"invalid": True}


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return round(2 * precision * recall / (precision + recall), 6)


def _format_ratio(value: object) -> str:
    return f"{float(value):.3f}"


def _format_bounded_ids(value: object, *, limit: int = 20) -> str:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return "-"
    identifiers = [str(item) for item in value]
    shown = identifiers[:limit]
    suffix = "" if len(identifiers) <= limit else f" ... (+{len(identifiers) - limit})"
    return ", ".join(shown) + suffix


def _parse_scenario(
    record: dict[str, Any],
    path: Path,
    line_no: int,
    *,
    schema_version: int,
    dataset_version: str,
    files_per_scenario: int,
    file_keys: frozenset[str],
) -> DiscoveryScenario:
    location = f"{path}:{line_no}"
    _require_exact_keys(record, _SCENARIO_KEYS, location)
    _require_version(
        record,
        location,
        schema_version=schema_version,
        dataset_version=dataset_version,
    )
    if record["provenance"] != "synthetic":
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: provenance must be synthetic"
        )
    raw_files = record["files"]
    if not isinstance(raw_files, list) or len(raw_files) != files_per_scenario:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: every scenario must contain exactly "
            f"{files_per_scenario} files"
        )
    files = tuple(
        _parse_file(raw_file, location, index, file_keys=file_keys)
        for index, raw_file in enumerate(raw_files)
    )
    return DiscoveryScenario(
        scenario_id=_require_identifier(record["id"], "id", location),
        split=_require_choice(record["split"], SUPPORTED_SPLITS, "split", location),
        profile=_require_identifier(record["profile"], "profile", location),
        files=files,
        tags=_require_tags(record["tags"], location),
        rationale=_require_nonempty_string(
            record["rationale"], "rationale", location
        ),
    )


def _parse_file(
    value: object,
    scenario_location: str,
    index: int,
    *,
    file_keys: frozenset[str],
) -> DiscoveryFileFixture:
    location = f"{scenario_location}.files[{index}]"
    if not isinstance(value, dict):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: file fixture must be an object"
        )
    _require_exact_keys(value, file_keys, location)
    file_id = _require_identifier(value["id"], "id", location)
    relative_path = _require_relative_path(value["path"], location)
    category = _require_choice(
        value["category"], SUPPORTED_CATEGORIES, "category", location
    )
    content = _require_nonempty_string(value["content"], "content", location)
    _validate_fixture_text(content, "content", location)
    expected_selector = _parse_expected_selector(
        value["expected_selector"], category, location
    )
    canaries_value = value["canaries"]
    if not isinstance(canaries_value, list):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: canaries must be a list"
        )
    canaries: list[str] = []
    for canary_index, raw_canary in enumerate(canaries_value):
        canary = _require_nonempty_string(
            raw_canary,
            f"canaries[{canary_index}]",
            location,
        )
        if len(canary.encode("utf-8")) < 12 or canary not in content:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: each canary must be at least 12 bytes and occur in content"
            )
        canaries.append(canary)
    if category in {"supported_positive", "out_of_scope_protected"} and not canaries:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: protected fixtures require a privacy canary"
        )
    _validate_category_path(category, relative_path, location)
    if file_keys == _V2_FILE_KEYS:
        challenge_family = _require_identifier(
            value["challenge_family"], "challenge_family", location
        )
        raw_counterfactual_group = value["counterfactual_group"]
        counterfactual_group = (
            None
            if raw_counterfactual_group is None
            else _require_identifier(
                raw_counterfactual_group, "counterfactual_group", location
            )
        )
    else:
        challenge_family = category
        counterfactual_group = None
    return DiscoveryFileFixture(
        file_id=file_id,
        relative_path=relative_path,
        category=category,
        content=content,
        expected_selector=expected_selector,
        canaries=tuple(canaries),
        tags=_require_tags(value["tags"], location),
        rationale=_require_nonempty_string(value["rationale"], "rationale", location),
        challenge_family=challenge_family,
        counterfactual_group=counterfactual_group,
    )


def _parse_expected_selector(
    value: object,
    category: str,
    location: str,
) -> dict[str, tuple[str, ...]] | None:
    if category != "supported_positive":
        if value is not None:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: only supported positives may declare a selector"
            )
        return None
    if not isinstance(value, dict) or len(value) != 1:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: supported positive requires one selector kind"
        )
    kind = next(iter(value))
    values = value[kind]
    if (
        kind not in {"dotenv_keys", "json_pointers"}
        or not isinstance(values, list)
        or not values
        or not all(isinstance(item, str) and item for item in values)
        or len(values) != len(set(values))
        or values != sorted(values)
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: expected selector is invalid"
        )
    return {kind: tuple(values)}


def _validate_dataset(
    scenarios: Sequence[DiscoveryScenario],
    expected_counts: Mapping[str, int],
    path: Path,
    *,
    category_counts_per_scenario: Mapping[str, int],
    challenge_family_counts_per_scenario: Mapping[str, int],
    require_disjoint_profiles: bool,
) -> None:
    scenario_ids = [scenario.scenario_id for scenario in scenarios]
    file_ids = [
        fixture.file_id for scenario in scenarios for fixture in scenario.files
    ]
    for label, identifiers in (("scenario", scenario_ids), ("file", file_ids)):
        duplicates = sorted(
            {item for item in identifiers if identifiers.count(item) > 1}
        )
        if duplicates:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{path}: duplicate {label} ids: {', '.join(duplicates)}"
            )
    for scenario in scenarios:
        paths = [fixture.relative_path for fixture in scenario.files]
        if len(paths) != len(set(paths)):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{path}: scenario {scenario.scenario_id} has duplicate paths"
            )
        category_counts = Counter(fixture.category for fixture in scenario.files)
        if category_counts != dict(category_counts_per_scenario):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{path}: scenario {scenario.scenario_id} category template drifted"
            )
        if challenge_family_counts_per_scenario:
            family_counts = Counter(
                fixture.challenge_family for fixture in scenario.files
            )
            if family_counts != dict(challenge_family_counts_per_scenario):
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{path}: scenario {scenario.scenario_id} challenge-family "
                    "template drifted"
                )
            for fixture in scenario.files:
                expected_category = (
                    "supported_positive"
                    if fixture.challenge_family.startswith("positive_")
                    else "supported_negative"
                    if fixture.challenge_family.startswith("negative_")
                    else fixture.challenge_family
                )
                if fixture.category != expected_category:
                    raise ProtectedSourceDiscoveryDatasetError(
                        f"{path}: challenge family/category contract drifted"
                    )
    observed = _selected_expected_counts(scenarios)
    observed["development_scenarios"] = sum(
        scenario.split == "development" for scenario in scenarios
    )
    observed["validation_scenarios"] = sum(
        scenario.split == "validation" for scenario in scenarios
    )
    if observed != dict(expected_counts):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: expected counts do not match corpus: {observed!r}"
        )
    profiles_by_split = {
        split: {scenario.profile for scenario in scenarios if scenario.split == split}
        for split in SUPPORTED_SPLITS
    }
    if (
        require_disjoint_profiles
        and profiles_by_split["development"] & profiles_by_split["validation"]
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: development and validation profiles must be disjoint"
        )
    if (
        not require_disjoint_profiles
        and profiles_by_split["development"] != profiles_by_split["validation"]
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: development and validation must cover the same profiles"
        )
    canaries = [
        canary
        for scenario in scenarios
        for fixture in scenario.files
        for canary in fixture.canaries
    ]
    duplicate_canaries = sorted(
        {canary for canary in canaries if canaries.count(canary) > 1}
    )
    if duplicate_canaries:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: privacy canaries must be globally unique"
        )
    safe_metadata = json.dumps(
        [
            {
                "id": fixture.file_id,
                "path": fixture.relative_path,
                "tags": fixture.tags,
                "rationale": fixture.rationale,
                "expected_selector": fixture.expected_selector,
            }
            for scenario in scenarios
            for fixture in scenario.files
        ],
        ensure_ascii=False,
        sort_keys=True,
    )
    if any(canary in safe_metadata for canary in canaries):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: privacy canaries may occur only in fixture content"
        )


def _parse_expected_counts(value: object, location: object) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != _EXPECTED_COUNT_KEYS:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: expected_counts keys are invalid"
        )
    result: dict[str, int] = {}
    for key, item in value.items():
        if type(item) is not int or item <= 0:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: expected_counts.{key} must be a positive integer"
            )
        result[key] = item
    return result


def _parse_go_no_go(
    value: object,
    location: object,
    *,
    keys: frozenset[str] = _GO_NO_GO_KEYS,
) -> dict[str, float]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: go_no_go keys are invalid"
        )
    result: dict[str, float] = {}
    for key, item in value.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: go_no_go.{key} must be numeric"
            )
        number = float(item)
        maximum = (
            10_000.0
            if key == "maximum_workspace_candidate_median"
            else 1.0
        )
        if not math.isfinite(number) or not 0.0 <= number <= maximum:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: go_no_go.{key} is outside the supported range"
            )
        result[key] = number
    return result


def _parse_baseline(
    value: object,
    location: object,
    *,
    keys: frozenset[str] = _BASELINE_KEYS,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: baseline keys are invalid"
        )
    detector_version = value["detector_version"]
    if not isinstance(detector_version, str) or not detector_version:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: baseline detector_version is invalid"
        )
    result: dict[str, object] = {"detector_version": detector_version}
    for key, item in value.items():
        if key == "detector_version":
            continue
        if key in {"case_outcomes_sha256", "scenario_outcomes_sha256"}:
            if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None:
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{location}: baseline.{key} must be a SHA-256 digest"
                )
            result[key] = item
        elif key == "workspace_candidate_median":
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{location}: baseline median must be numeric"
                )
            result[key] = float(item)
        elif type(item) is not int or item < 0:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: baseline.{key} must be a non-negative integer"
            )
        else:
            result[key] = item
    return result


def _parse_v2_baselines(
    value: object,
    location: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {"all", *SUPPORTED_SPLITS}:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: baselines must contain all, development, and validation"
        )
    baselines = {
        split: _parse_baseline(
            baseline,
            f"{location}.baselines.{split}",
            keys=_V2_BASELINE_KEYS,
        )
        for split, baseline in sorted(value.items())
    }
    versions = {baseline["detector_version"] for baseline in baselines.values()}
    if len(versions) != 1:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: v2 baselines must use one detector version"
        )
    return baselines


def _parse_v2_scenario_contract(
    value: object,
    location: object,
) -> tuple[
    int,
    dict[str, int],
    dict[str, int],
    tuple[str, ...],
    tuple[str, ...],
    dict[str, str],
    dict[str, str],
]:
    if not isinstance(value, dict):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: scenario_contract must be an object"
        )
    _require_exact_keys(value, _V2_SCENARIO_CONTRACT_KEYS, location)
    files_per_scenario = value["files_per_scenario"]
    if type(files_per_scenario) is not int or files_per_scenario <= 0:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: files_per_scenario must be a positive integer"
        )
    category_counts = _parse_positive_integer_map(
        value["category_counts"],
        f"{location}.scenario_contract.category_counts",
        expected_keys=SUPPORTED_CATEGORIES,
    )
    challenge_family_counts = _parse_positive_integer_map(
        value["challenge_family_counts"],
        f"{location}.scenario_contract.challenge_family_counts",
    )
    if (
        sum(category_counts.values()) != files_per_scenario
        or sum(challenge_family_counts.values()) != files_per_scenario
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: scenario_contract counts do not match files_per_scenario"
        )
    hard_positive_families = _parse_identifier_list(
        value["hard_positive_families"],
        f"{location}.scenario_contract.hard_positive_families",
    )
    negative_families = _parse_identifier_list(
        value["negative_families"],
        f"{location}.scenario_contract.negative_families",
    )
    known_families = set(challenge_family_counts)
    if not set(hard_positive_families) <= known_families or not set(
        negative_families
    ) <= known_families:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: scenario_contract references an unknown challenge family"
        )
    if any(not family.startswith("positive_") for family in hard_positive_families):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: hard-positive families must use the positive_ prefix"
        )
    if any(not family.startswith("negative_") for family in negative_families):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: negative families must use the negative_ prefix"
        )
    profile_prefixes = _parse_split_string_map(
        value["profile_prefixes"],
        f"{location}.scenario_contract.profile_prefixes",
        require_digest=False,
    )
    split_shape_sha256 = _parse_split_string_map(
        value["split_shape_sha256"],
        f"{location}.scenario_contract.split_shape_sha256",
        require_digest=True,
    )
    return (
        files_per_scenario,
        category_counts,
        challenge_family_counts,
        hard_positive_families,
        negative_families,
        profile_prefixes,
        split_shape_sha256,
    )


def _parse_split_string_map(
    value: object,
    location: object,
    *,
    require_digest: bool,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != SUPPORTED_SPLITS:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: split keys are invalid"
        )
    result: dict[str, str] = {}
    for split, item in value.items():
        text = _require_nonempty_string(item, split, location)
        if require_digest and re.fullmatch(r"[0-9a-f]{64}", text) is None:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}.{split} must be a SHA-256 digest"
            )
        result[split] = text
    if len(set(result.values())) != len(result):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: split values must be distinct"
        )
    return result


def _parse_positive_integer_map(
    value: object,
    location: object,
    *,
    expected_keys: frozenset[str] | None = None,
) -> dict[str, int]:
    if not isinstance(value, dict) or not value:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: expected a non-empty object"
        )
    if expected_keys is not None and set(value) != expected_keys:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: keys are invalid"
        )
    result: dict[str, int] = {}
    for key, item in value.items():
        identifier = _require_identifier(key, "key", location)
        if type(item) is not int or item <= 0:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}.{identifier} must be a positive integer"
            )
        result[identifier] = item
    return result


def _parse_identifier_list(value: object, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: expected a non-empty identifier list"
        )
    result = tuple(
        _require_identifier(item, "item", location) for item in value
    )
    if len(result) != len(set(result)) or list(result) != sorted(result):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: identifiers must be unique and sorted"
        )
    return result


def _parse_v2_vocabulary(
    value: dict[str, Any],
    location: object,
) -> tuple[
    dict[str, dict[str, tuple[str, ...]]],
    tuple[str, ...],
    float,
]:
    _require_exact_keys(value, _V2_VOCABULARY_KEYS, location)
    _require_version(
        value,
        location,
        schema_version=V2_DATASET_SCHEMA_VERSION,
        dataset_version=V2_DATASET_VERSION,
    )
    if value["normalization"] != "unicode-casefold-alnum-segments-v1":
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: unsupported vocabulary normalization"
        )
    shared_format_tokens = _parse_vocabulary_values(
        value["shared_format_tokens"], f"{location}.shared_format_tokens"
    )
    maximum_overlap = value["maximum_cross_split_feature_overlap"]
    if (
        isinstance(maximum_overlap, bool)
        or not isinstance(maximum_overlap, (int, float))
        or not 0.0 <= float(maximum_overlap) < 1.0
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: maximum cross-split feature overlap is invalid"
        )
    raw_splits = value["splits"]
    if not isinstance(raw_splits, dict) or set(raw_splits) != SUPPORTED_SPLITS:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: vocabulary splits are invalid"
        )
    result: dict[str, dict[str, tuple[str, ...]]] = {}
    for split in sorted(SUPPORTED_SPLITS):
        raw_split = raw_splits[split]
        if not isinstance(raw_split, dict):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: vocabulary split must be an object"
            )
        _require_exact_keys(
            raw_split, _V2_VOCABULARY_SPLIT_KEYS, f"{location}.{split}"
        )
        result[split] = {
            dimension: _parse_vocabulary_values(
                raw_split[dimension], f"{location}.{split}.{dimension}"
            )
            for dimension in sorted(_V2_VOCABULARY_SPLIT_KEYS)
        }
    for dimension in sorted(_V2_VOCABULARY_SPLIT_KEYS):
        development = {
            _normalize_vocabulary_token(item)
            for item in result["development"][dimension]
        }
        validation = {
            _normalize_vocabulary_token(item)
            for item in result["validation"][dimension]
        }
        if development & validation:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: split vocabulary overlaps in {dimension}"
            )
    return result, shared_format_tokens, float(maximum_overlap)


def _parse_vocabulary_values(value: object, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: vocabulary must be a non-empty list"
        )
    values = tuple(
        _require_nonempty_string(item, "item", location) for item in value
    )
    if len(values) != len(set(values)) or list(values) != sorted(values):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: vocabulary must be unique and sorted"
        )
    normalized = tuple(_normalize_vocabulary_token(item) for item in values)
    if any(not item for item in normalized) or len(normalized) != len(set(normalized)):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: normalized vocabulary must be non-empty and unique"
        )
    return values


def _normalize_vocabulary_token(value: str) -> str:
    normalized = "_".join(
        part
        for part in re.sub(r"[^\w]+", "_", value, flags=re.UNICODE)
        .strip("_")
        .casefold()
        .split("_")
        if part
    )
    if normalized:
        return normalized
    return "punct_" + "_".join(f"{ord(character):x}" for character in value)


def _validate_v2_vocabulary(
    scenarios: Sequence[DiscoveryScenario],
    vocabulary: Mapping[str, Mapping[str, Sequence[str]]],
    *,
    shared_vocabulary_tokens: Sequence[str],
    maximum_feature_overlap: float,
    location: object,
) -> float:
    paths_by_split: dict[str, set[str]] = {}
    selectors_by_split: dict[str, set[str]] = {}
    corpus_blobs: dict[str, tuple[str, str]] = {}
    features_by_split: dict[str, set[str]] = {}
    for split in sorted(SUPPORTED_SPLITS):
        split_scenarios = [item for item in scenarios if item.split == split]
        fixtures = [fixture for item in split_scenarios for fixture in item.files]
        content = "\n".join(fixture.content for fixture in fixtures)
        paths = "\n".join(fixture.relative_path for fixture in fixtures)
        normalized_content = _normalize_vocabulary_token(content)
        normalized_paths = _normalize_vocabulary_token(paths)
        for dimension in ("pattern_tokens", "placeholder_values", "protocol_values"):
            for token in vocabulary[split][dimension]:
                if (
                    token not in content
                    and _normalize_vocabulary_token(token) not in normalized_content
                ):
                    raise ProtectedSourceDiscoveryDatasetError(
                        f"{location}: {split} {dimension} token is unused"
                    )
        for token in vocabulary[split]["path_tokens"]:
            if (
                token not in paths
                and _normalize_vocabulary_token(token) not in normalized_paths
            ):
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{location}: {split} path token is unused"
                )
        canaries = [canary for fixture in fixtures for canary in fixture.canaries]
        for prefix in vocabulary[split]["canary_prefixes"]:
            if not any(canary.startswith(prefix) for canary in canaries):
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{location}: {split} canary prefix is unused"
                )
        paths_by_split[split] = {fixture.relative_path for fixture in fixtures}
        canary_text = "\n".join(canaries)
        raw_blob = "\n".join((content, paths, canary_text))
        corpus_blobs[split] = (raw_blob, _normalize_vocabulary_token(raw_blob))
        features_by_split[split] = _split_detector_features(fixtures)
        selectors_by_split[split] = {
            _normalize_vocabulary_token(_selector_terminal(value))
            for fixture in fixtures
            if fixture.expected_selector is not None
            for values in fixture.expected_selector.values()
            for value in values
        }
    if paths_by_split["development"] & paths_by_split["validation"]:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: development and validation paths must be disjoint"
        )
    if selectors_by_split["development"] & selectors_by_split["validation"]:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: development and validation selector vocabulary overlaps"
        )
    for split in sorted(SUPPORTED_SPLITS):
        other = "validation" if split == "development" else "development"
        other_raw, other_normalized = corpus_blobs[other]
        normalized_blob = f"_{other_normalized}_"
        for dimension in sorted(_V2_VOCABULARY_SPLIT_KEYS):
            for token in vocabulary[split][dimension]:
                normalized_token = _normalize_vocabulary_token(token)
                if token in other_raw or f"_{normalized_token}_" in normalized_blob:
                    raise ProtectedSourceDiscoveryDatasetError(
                        f"{location}: {split} declared vocabulary appears in "
                        f"the {other} corpus"
                    )
    shared = {
        _normalize_vocabulary_token(item) for item in shared_vocabulary_tokens
    }
    development_features = features_by_split["development"] - shared
    validation_features = features_by_split["validation"] - shared
    overlap = _ratio(
        len(development_features & validation_features),
        len(development_features | validation_features),
    )
    if overlap > maximum_feature_overlap:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: undeclared cross-split feature overlap is too high"
        )
    return overlap


def _split_detector_features(
    fixtures: Sequence[DiscoveryFileFixture],
) -> set[str]:
    features: set[str] = set()
    for fixture in fixtures:
        for part in PurePosixPath(fixture.relative_path).parts:
            features.update(_vocabulary_segments(part))
        name = PurePosixPath(fixture.relative_path).name.casefold()
        if name == ".env" or name.startswith(".env."):
            for raw_line in fixture.content.splitlines():
                match = re.match(r"^(?:export\s+)?([^=\s]+)\s*=", raw_line.strip())
                if match is not None:
                    features.add(_normalize_vocabulary_token(match.group(1)))
        elif name.endswith(".json"):
            try:
                value = json.loads(fixture.content)
            except (json.JSONDecodeError, RecursionError):
                continue
            stack = [value]
            while stack:
                current = stack.pop()
                if isinstance(current, dict):
                    features.update(
                        _normalize_vocabulary_token(str(key)) for key in current
                    )
                    stack.extend(current.values())
                elif isinstance(current, list):
                    stack.extend(current)
    return {item for item in features if item and not item.isdigit()}


def _vocabulary_segments(value: str) -> set[str]:
    return {
        part
        for part in _normalize_vocabulary_token(value).split("_")
        if part and not part.isdigit()
    }


def _selector_terminal(value: str) -> str:
    if not value.startswith("/"):
        return value
    return value.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")


def _validate_counterfactual_groups(
    scenarios: Sequence[DiscoveryScenario],
    location: object,
) -> None:
    groups: dict[str, list[tuple[DiscoveryScenario, DiscoveryFileFixture]]] = (
        defaultdict(list)
    )
    mixed_count = 0
    for scenario in scenarios:
        for fixture in scenario.files:
            if fixture.challenge_family == "positive_mixed_selector":
                mixed_count += 1
                if (
                    fixture.category != "supported_positive"
                    or fixture.expected_selector is None
                    or sum(map(len, fixture.expected_selector.values())) != 1
                    or "mixed_selector" not in fixture.tags
                ):
                    raise ProtectedSourceDiscoveryDatasetError(
                        f"{location}: mixed-selector fixture contract drifted"
                    )
            if fixture.counterfactual_group is not None:
                groups[fixture.counterfactual_group].append((scenario, fixture))
    if mixed_count != len(scenarios) or len(groups) != len(scenarios):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: counterfactual coverage does not match scenarios"
        )
    for group, items in groups.items():
        if len(items) != 2:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: counterfactual group {group} must contain two files"
            )
        splits = {scenario.split for scenario, _fixture in items}
        families = {fixture.challenge_family for _scenario, fixture in items}
        categories = {fixture.category for _scenario, fixture in items}
        paths = {fixture.relative_path for _scenario, fixture in items}
        if (
            len(splits) != 1
            or families
            != {"positive_path_decoy", "negative_documentation_example"}
            or categories != {"supported_positive", "supported_negative"}
            or len(paths) != 1
        ):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: counterfactual group {group} is not path matched"
            )


def _validate_v2_shape_contract(
    scenarios: Sequence[DiscoveryScenario],
    *,
    profile_prefixes: Mapping[str, str],
    expected_shape_sha256: Mapping[str, str],
    location: object,
) -> None:
    observed: dict[str, str] = {}
    for split in sorted(SUPPORTED_SPLITS):
        selected = tuple(item for item in scenarios if item.split == split)
        prefix = profile_prefixes[split]
        if not all(item.profile.startswith(prefix) for item in selected):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: {split} profile prefix contract drifted"
            )
        observed[split] = _split_shape_digest(selected)
        if observed[split] != expected_shape_sha256[split]:
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: {split} shape digest drifted"
            )
    if len(set(observed.values())) != len(observed):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: split shape digests must be distinct"
        )


def _split_shape_digest(scenarios: Sequence[DiscoveryScenario]) -> str:
    payload = [
        {
            "files": [
                {
                    "family": fixture.challenge_family,
                    "path_depth": len(PurePosixPath(fixture.relative_path).parts),
                    "selector_shape": _selector_shape(fixture.expected_selector),
                    "source_shape": _fixture_source_shape(fixture),
                }
                for fixture in scenario.files
            ],
        }
        for scenario in sorted(scenarios, key=lambda item: item.scenario_id)
    ]
    return _outcomes_digest(
        b"tooluseproxy-protected-source-discovery-split-shape-v1\0",
        payload,
    )


def _fixture_source_shape(fixture: DiscoveryFileFixture) -> object:
    name = PurePosixPath(fixture.relative_path).name.casefold()
    if name == ".env" or name.startswith(".env."):
        assignments: list[str] = []
        for raw_line in fixture.content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^(?:export\s+)?([^=\s]+)\s*=\s*(.*)$", line)
            if match is None:
                assignments.append("invalid")
                continue
            raw_value = match.group(2)
            quote = (
                "single"
                if raw_value.startswith("'")
                else "double"
                if raw_value.startswith('"')
                else "unquoted"
            )
            assignments.append(quote)
        return {"kind": "dotenv", "assignments": assignments}
    if name.endswith(".json"):
        try:
            value = json.loads(fixture.content)
        except (json.JSONDecodeError, RecursionError):
            return {"kind": "json", "shape": "<invalid>"}
        return {"kind": "json", "shape": _json_value_shape(value)}
    return {
        "kind": "other",
        "suffix": PurePosixPath(fixture.relative_path).suffix.casefold(),
        "line_count": len(fixture.content.splitlines()),
    }


def _json_value_shape(value: object) -> object:
    if isinstance(value, dict):
        children = [_json_value_shape(child) for child in value.values()]
        return {
            "object": sorted(
                children,
                key=lambda child: json.dumps(
                    child, ensure_ascii=False, sort_keys=True
                ),
            )
        }
    if isinstance(value, list):
        return [_json_value_shape(child) for child in value]
    if isinstance(value, str):
        return "<string>"
    if value is None:
        return "<null>"
    if isinstance(value, bool):
        return "<boolean>"
    return "<number>"


def _selector_shape(
    selector: Mapping[str, Sequence[str]] | None,
) -> dict[str, object] | None:
    if selector is None:
        return None
    kind = next(iter(selector))
    values = selector[kind]
    return {
        "kind": kind,
        "count": len(values),
        "depths": sorted(value.count("/") for value in values),
    }


def _validate_category_path(category: str, relative_path: str, location: str) -> None:
    name = PurePosixPath(relative_path).name.casefold()
    supported = name == ".env" or name.startswith(".env.") or name.endswith(".json")
    if category in {"supported_positive", "supported_negative"} and not supported:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: supported fixture path is outside the supported formats"
        )
    if category == "out_of_scope_protected" and supported:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: out-of-scope fixture uses a supported source format"
        )


def _validate_fixture_text(text: str, field: str, location: object) -> None:
    for label, pattern in _FORBIDDEN_SECRET_PATTERNS:
        if pattern.search(text):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: {field} resembles a real {label}"
            )


def _require_relative_path(value: object, location: object) -> str:
    text = _require_nonempty_string(value, "path", location)
    if "\\" in text or "\x00" in text or any(ord(character) < 32 for character in text):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: path must be normalized POSIX text"
        )
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: path must remain inside the workspace"
        )
    if path.as_posix() != text or text == "protected_sources.json":
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: path is not a valid fixture path"
        )
    return text


def _require_identifier(value: object, field: str, location: object) -> str:
    text = _require_nonempty_string(value, field, location)
    if not _ID_PATTERN.fullmatch(text):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: {field} must be a lowercase identifier"
        )
    return text


def _require_tags(value: object, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: tags must be a non-empty list"
        )
    tags: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _TAG_PATTERN.fullmatch(item):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{location}: tags must be lowercase identifiers"
            )
        tags.append(item)
    if len(tags) != len(set(tags)):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: tags must be unique"
        )
    return tuple(tags)


def _require_choice(
    value: object,
    choices: frozenset[str],
    field: str,
    location: object,
) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: {field} must be one of {sorted(choices)}"
        )
    return value


def _require_nonempty_string(value: object, field: str, location: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: {field} must be a non-empty string"
        )
    return value


def _require_exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    location: object,
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: schema mismatch missing={missing} unknown={unknown}"
        )


def _require_version(
    value: Mapping[str, object],
    location: object,
    *,
    schema_version: int,
    dataset_version: str,
) -> None:
    if (
        value.get("schema_version") != schema_version
        or value.get("dataset_version") != dataset_version
    ):
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: unsupported discovery dataset version"
        )


def _resolve_fixture_file(
    root: Path,
    value: object,
    field: str,
    location: object,
) -> Path:
    if not isinstance(value, str) or PurePosixPath(value).name != value:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: {field} must be a local file name"
        )
    path = root / value
    if not path.is_file():
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: {field} does not exist"
        )
    return path


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = _strict_json_loads(path.read_text(encoding="utf-8"), path)
    except (OSError, UnicodeError) as error:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: could not read JSON"
        ) from error
    if not isinstance(value, dict):
        raise ProtectedSourceDiscoveryDatasetError(f"{path}: JSON root must be an object")
    return value


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{path}: could not read JSONL"
        ) from error
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            raise ProtectedSourceDiscoveryDatasetError(
                f"{path}:{line_no}: blank JSONL lines are not allowed"
            )
        value = _strict_json_loads(line, f"{path}:{line_no}")
        if not isinstance(value, dict):
            raise ProtectedSourceDiscoveryDatasetError(
                f"{path}:{line_no}: record must be an object"
            )
        records.append((line_no, value))
    return records


def _strict_json_loads(text: str, location: object) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProtectedSourceDiscoveryDatasetError(
                    f"{location}: duplicate JSON key"
                )
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: non-finite JSON number"
        )

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ProtectedSourceDiscoveryDatasetError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ProtectedSourceDiscoveryDatasetError(
            f"{location}: invalid JSON"
        ) from error


def _dataset_digest(paths: tuple[Path, ...], *, domain: bytes) -> str:
    digest = hashlib.sha256(domain)
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
