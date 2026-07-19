from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DATASET_SCHEMA_VERSION = 1
SUPPORTED_DATASET_VERSION = "1.0.0"
V1_DATASET_VERSION = "1.0.0"
V2_DATASET_VERSION = "2.0.0"
V21_DATASET_VERSION = "2.1.0"
V1_DATASET_SCHEMA_VERSION = 1
V2_DATASET_SCHEMA_VERSION = 2
V21_DATASET_SCHEMA_VERSION = 3
SUPPORTED_SPLITS = frozenset({"development", "validation"})
SUPPORTED_PAIR_SCOPES = frozenset({"artifact_flow", "source_binding"})
SUPPORTED_SOURCE_BINDING_SIGNALS = frozenset(
    {
        "not_applicable",
        "registered_source",
        "selected_field",
        "selected_security_field",
    }
)
SUPPORTED_ACTIONS = frozenset({"allow", "warn", "block", "continue_review"})
SUPPORTED_SINK_TYPES = frozenset(
    {
        "external_api_call",
        "external_http_request",
        "external_message",
        "external_search",
        "final_answer",
    }
)

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_FORBIDDEN_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI-style token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
)
_V1_MANIFEST_KEYS = frozenset(
    {"schema_version", "dataset_id", "dataset_version", "description", "files"}
)
_V2_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_version",
        "description",
        "files",
        "expected_counts",
        "go_no_go",
        "baselines",
        "family_contract",
    }
)
_V21_MANIFEST_KEYS = _V2_MANIFEST_KEYS | frozenset({"stress_contract"})
_V1_PAIR_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "scope",
        "provenance",
        "left_text",
        "right_text",
        "should_link",
        "observe_only",
        "tags",
        "rationale",
    }
)
_V2_PAIR_KEYS = _V1_PAIR_KEYS | frozenset({"family", "counterfactual_group"})
_V21_PAIR_KEYS = _V2_PAIR_KEYS | frozenset({"source_binding_signal"})
_V1_SCENARIO_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "provenance",
        "source_text",
        "artifact_texts",
        "sink_type",
        "should_reach_sink",
        "expected_action",
        "observe_only",
        "tags",
        "rationale",
    }
)
_V2_SCENARIO_KEYS = _V1_SCENARIO_KEYS | frozenset(
    {"family", "counterfactual_group"}
)
_V21_SCENARIO_KEYS = _V2_SCENARIO_KEYS | frozenset({"source_binding_signal"})
_RETRIEVAL_POOL_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "scope",
        "provenance",
        "family",
        "counterfactual_group",
        "query_text",
        "relevant_candidate_id",
        "candidates",
        "observe_only",
        "tags",
        "rationale",
    }
)
_V21_RETRIEVAL_POOL_KEYS = _RETRIEVAL_POOL_KEYS | frozenset(
    {"source_binding_signal"}
)
_RETRIEVAL_CANDIDATE_KEYS = frozenset({"id", "text", "sequence_no"})
_RETRIEVAL_CANDIDATE_SERIES_KEYS = frozenset(
    {"id_prefix", "decoy_text_prefix", "relevant_text", "count"}
)
_RETRIEVAL_CONSTANT_DECOY_SERIES_KEYS = frozenset(
    {
        "id_prefix",
        "matching_decoy_text",
        "matching_decoy_count",
        "filler_text_prefix",
        "relevant_text",
        "count",
    }
)
_TEXT_RECIPE_KEYS = frozenset(
    {"head", "head_count", "middle", "tail", "tail_count"}
)
_EXPECTED_COUNT_KEYS = frozenset(
    {
        "pairs",
        "scenarios",
        "retrieval_pools",
        "development_pairs",
        "validation_pairs",
        "development_scenarios",
        "validation_scenarios",
        "development_retrieval_pools",
        "validation_retrieval_pools",
        "development_gate_pairs",
        "validation_gate_pairs",
        "development_gate_scenarios",
        "validation_gate_scenarios",
        "development_gate_retrieval_pools",
        "validation_gate_retrieval_pools",
    }
)
_GO_NO_GO_KEYS = frozenset(
    {
        "minimum_pair_precision",
        "minimum_pair_recall",
        "minimum_pair_f1",
        "minimum_artifact_candidate_recall",
        "minimum_source_candidate_recall",
        "minimum_e2e_reachability_f1",
        "minimum_e2e_action_accuracy",
        "minimum_family_accuracy",
        "maximum_false_blocks",
        "maximum_privacy_exposures",
    }
)
_BASELINE_KEYS = frozenset(
    {
        "pair_tp",
        "pair_fp",
        "pair_tn",
        "pair_fn",
        "artifact_candidate_positive_cases",
        "artifact_candidate_retrieved",
        "source_candidate_positive_cases",
        "source_candidate_retrieved",
        "e2e_tp",
        "e2e_fp",
        "e2e_tn",
        "e2e_fn",
        "e2e_action_correct",
        "e2e_action_cases",
        "parity_mismatches",
        "pair_outcomes_sha256",
        "candidate_outcomes_sha256",
        "scenario_outcomes_sha256",
        "privacy_exposures",
    }
)
_FAMILY_CONTRACT_KEYS = frozenset(
    {
        "pair_families",
        "candidate_families",
        "scenario_families",
        "counterfactual_groups_per_split",
        "minimum_artifact_pool_size",
        "minimum_source_pool_size",
        "maximum_split_vocabulary_jaccard",
        "maximum_split_feature_jaccard",
        "development_shape_sha256",
        "validation_shape_sha256",
    }
)
_SPLIT_MAP_KEYS = frozenset({"development", "validation"})
_STRESS_CONTRACT_KEYS = frozenset(
    {
        "generated_pool_sizes",
        "maximum_candidate_count",
        "minimum_saturation_rate",
    }
)
_MAX_EXPANDED_FIXTURE_TEXT_CHARS = 65_536
_MAX_RETRIEVAL_POOL_TEXT_CHARS = 4 * 1024 * 1024
_V2_MAX_RETRIEVAL_CANDIDATES = 1_000
_V21_MAX_RETRIEVAL_CANDIDATES = 10_000
_SPLIT_CONTRACT_STOP_TOKENS = frozenset(
    {
        "access",
        "after",
        "allowed",
        "approved",
        "artifact",
        "authentication",
        "before",
        "candidate",
        "data",
        "field",
        "from",
        "private",
        "public",
        "route",
        "source",
        "status",
        "synthetic",
        "that",
        "this",
        "token",
        "value",
        "with",
        "wrapper",
    }
)
_DATASET_REGISTRY = {
    (V1_DATASET_SCHEMA_VERSION, V1_DATASET_VERSION): {
        "digest": "066036e02e0b3747f59a0fa09ccd0352c7df6a9a5b6a65870163735639e3a848",
        "files": frozenset({"pairs", "scenarios"}),
    },
    (V2_DATASET_SCHEMA_VERSION, V2_DATASET_VERSION): {
        "digest": "241a4f536ea53694b8172accc5a528961673a843983f99702651357cff3619b3",
        "files": frozenset({"pairs", "scenarios", "retrieval_pools"}),
    },
    (V21_DATASET_SCHEMA_VERSION, V21_DATASET_VERSION): {
        "digest": "eaae7a5e97c79e59f8d45706466170fe93cc66c2c2e6293d82f5721ef32d7cf4",
        "files": frozenset({"pairs", "scenarios", "retrieval_pools"}),
    },
}


class SimilarityDatasetError(ValueError):
    """Raised when a versioned similarity fixture violates its contract."""


@dataclass(frozen=True)
class PairExample:
    example_id: str
    split: str
    scope: str
    left_text: str
    right_text: str
    should_link: bool
    observe_only: bool
    tags: tuple[str, ...]
    rationale: str
    family: str = "v1_pair"
    counterfactual_group: str | None = None
    source_binding_signal: str = "not_applicable"

    @property
    def minimum_length(self) -> int:
        return 4 if self.scope == "source_binding" else 8


@dataclass(frozen=True)
class LineageScenario:
    scenario_id: str
    split: str
    source_text: str
    artifact_texts: tuple[str, ...]
    sink_type: str
    should_reach_sink: bool
    expected_action: str
    observe_only: bool
    tags: tuple[str, ...]
    rationale: str
    family: str = "v1_scenario"
    counterfactual_group: str | None = None
    source_binding_signal: str = "registered_source"


@dataclass(frozen=True)
class RetrievalPoolCandidate:
    candidate_id: str
    text: str
    sequence_no: int


@dataclass(frozen=True)
class RetrievalPool:
    pool_id: str
    split: str
    scope: str
    family: str
    counterfactual_group: str | None
    query_text: str
    relevant_candidate_id: str
    candidates: tuple[RetrievalPoolCandidate, ...]
    observe_only: bool
    tags: tuple[str, ...]
    rationale: str
    source_binding_signal: str = "not_applicable"


@dataclass(frozen=True)
class SimilarityDataset:
    dataset_id: str
    dataset_version: str
    description: str
    digest_sha256: str
    pairs: tuple[PairExample, ...]
    scenarios: tuple[LineageScenario, ...]
    schema_version: int = V1_DATASET_SCHEMA_VERSION
    pinned_digest_sha256: str = _DATASET_REGISTRY[
        (V1_DATASET_SCHEMA_VERSION, V1_DATASET_VERSION)
    ]["digest"]
    retrieval_pools: tuple[RetrievalPool, ...] = ()
    expected_counts: dict[str, int] | None = None
    go_no_go: dict[str, float] | None = None
    baselines: dict[str, dict[str, object]] | None = None
    family_contract: dict[str, object] | None = None
    split_contract: dict[str, object] | None = None
    stress_contract: dict[str, object] | None = None

    def select_pairs(self, split: str | None = None) -> tuple[PairExample, ...]:
        _validate_requested_split(split)
        if split is None:
            return self.pairs
        return tuple(item for item in self.pairs if item.split == split)

    def select_scenarios(
        self,
        split: str | None = None,
    ) -> tuple[LineageScenario, ...]:
        _validate_requested_split(split)
        if split is None:
            return self.scenarios
        return tuple(item for item in self.scenarios if item.split == split)

    def select_retrieval_pools(
        self,
        split: str | None = None,
    ) -> tuple[RetrievalPool, ...]:
        _validate_requested_split(split)
        if split is None:
            return self.retrieval_pools
        return tuple(item for item in self.retrieval_pools if item.split == split)

    def select_baseline(self, split: str | None) -> dict[str, object] | None:
        if self.baselines is None:
            return None
        return self.baselines[split or "all"]


def load_similarity_dataset(root: Path) -> SimilarityDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_json_object(manifest_path)
    schema_version = manifest.get("schema_version")
    dataset_version = manifest.get("dataset_version")
    registry_key = (schema_version, dataset_version)
    if registry_key not in _DATASET_REGISTRY:
        raise SimilarityDatasetError(
            f"{manifest_path}: unsupported schema/dataset version combination"
        )
    if registry_key == (V1_DATASET_SCHEMA_VERSION, V1_DATASET_VERSION):
        _require_exact_keys(manifest, _V1_MANIFEST_KEYS, manifest_path)
    elif registry_key == (V21_DATASET_SCHEMA_VERSION, V21_DATASET_VERSION):
        _require_exact_keys(manifest, _V21_MANIFEST_KEYS, manifest_path)
    else:
        _require_exact_keys(manifest, _V2_MANIFEST_KEYS, manifest_path)

    dataset_id = _require_identifier(manifest["dataset_id"], "dataset_id", manifest_path)
    description = _require_nonempty_string(
        manifest["description"],
        "description",
        manifest_path,
    )
    files = manifest["files"]
    expected_files = _DATASET_REGISTRY[registry_key]["files"]
    if not isinstance(files, dict) or set(files) != expected_files:
        raise SimilarityDatasetError(
            f"{manifest_path}: files do not match the registered dataset version"
        )
    pair_path = _resolve_fixture_file(root, files["pairs"], "files.pairs", manifest_path)
    scenario_path = _resolve_fixture_file(
        root,
        files["scenarios"],
        "files.scenarios",
        manifest_path,
    )
    retrieval_path = (
        _resolve_fixture_file(
            root,
            files["retrieval_pools"],
            "files.retrieval_pools",
            manifest_path,
        )
        if schema_version >= V2_DATASET_SCHEMA_VERSION
        else None
    )

    pair_records = _load_jsonl(pair_path)
    scenario_records = _load_jsonl(scenario_path)
    pairs = tuple(
        _parse_pair(
            record,
            pair_path,
            line_no,
            schema_version=int(schema_version),
            dataset_version=str(dataset_version),
        )
        for line_no, record in pair_records
    )
    scenarios = tuple(
        _parse_scenario(
            record,
            scenario_path,
            line_no,
            schema_version=int(schema_version),
            dataset_version=str(dataset_version),
        )
        for line_no, record in scenario_records
    )
    retrieval_pools = (
        tuple(
            _parse_retrieval_pool(
                record,
                retrieval_path,
                line_no,
                schema_version=int(schema_version),
                dataset_version=str(dataset_version),
            )
            for line_no, record in _load_jsonl(retrieval_path)
        )
        if retrieval_path is not None
        else ()
    )
    if not pairs:
        raise SimilarityDatasetError(f"{pair_path}: at least one pair is required")
    if not scenarios:
        raise SimilarityDatasetError(f"{scenario_path}: at least one scenario is required")

    all_ids = (
        [item.example_id for item in pairs]
        + [item.scenario_id for item in scenarios]
        + [item.pool_id for item in retrieval_pools]
    )
    duplicates = sorted({item_id for item_id in all_ids if all_ids.count(item_id) > 1})
    if duplicates:
        raise SimilarityDatasetError(
            f"dataset case ids must be unique: {', '.join(duplicates)}"
        )

    _validate_dataset_coverage(pairs, scenarios)
    expected_counts: dict[str, int] | None = None
    thresholds: dict[str, float] | None = None
    baselines: dict[str, dict[str, object]] | None = None
    family_contract: dict[str, object] | None = None
    split_contract: dict[str, object] | None = None
    stress_contract: dict[str, object] | None = None
    if schema_version >= V2_DATASET_SCHEMA_VERSION:
        expected_counts = _parse_expected_counts(
            manifest["expected_counts"], manifest_path
        )
        thresholds = _parse_thresholds(manifest["go_no_go"], manifest_path)
        baselines = _parse_baselines(manifest["baselines"], manifest_path)
        family_contract = _parse_family_contract(
            manifest["family_contract"], manifest_path
        )
        split_contract = _validate_v2_contract(
            pairs,
            scenarios,
            retrieval_pools,
            expected_counts=expected_counts,
            family_contract=family_contract,
            location=manifest_path,
        )
        if schema_version == V21_DATASET_SCHEMA_VERSION:
            stress_contract = _parse_stress_contract(
                manifest["stress_contract"], manifest_path
            )
            _validate_v21_stress_contract(
                retrieval_pools,
                stress_contract=stress_contract,
                location=manifest_path,
            )
    digest_paths = (manifest_path, pair_path, scenario_path) + (
        ((retrieval_path,) if retrieval_path is not None else ())
    )
    digest = _dataset_digest(digest_paths)
    pinned_digest = _DATASET_REGISTRY[registry_key]["digest"]
    assert isinstance(pinned_digest, str)
    return SimilarityDataset(
        dataset_id=dataset_id,
        dataset_version=str(dataset_version),
        description=description,
        digest_sha256=digest,
        pairs=pairs,
        scenarios=scenarios,
        schema_version=int(schema_version),
        pinned_digest_sha256=pinned_digest,
        retrieval_pools=retrieval_pools,
        expected_counts=expected_counts,
        go_no_go=thresholds,
        baselines=baselines,
        family_contract=family_contract,
        split_contract=split_contract,
        stress_contract=stress_contract,
    )


def _parse_pair(
    record: dict[str, Any],
    path: Path,
    line_no: int,
    *,
    schema_version: int,
    dataset_version: str,
) -> PairExample:
    location = f"{path}:{line_no}"
    is_versioned = schema_version >= V2_DATASET_SCHEMA_VERSION
    pair_keys = (
        _V21_PAIR_KEYS
        if schema_version == V21_DATASET_SCHEMA_VERSION
        else (_V2_PAIR_KEYS if is_versioned else _V1_PAIR_KEYS)
    )
    _require_exact_keys(record, pair_keys, location)
    _require_version(
        record,
        location,
        schema_version=schema_version,
        dataset_version=dataset_version,
    )
    _require_synthetic_provenance(record, location)
    split = _require_choice(record["split"], "split", SUPPORTED_SPLITS, location)
    scope = _require_choice(record["scope"], "scope", SUPPORTED_PAIR_SCOPES, location)
    left_text = _parse_fixture_text(
        record["left_text"],
        "left_text",
        location,
        allow_recipe=is_versioned,
    )
    right_text = _parse_fixture_text(
        record["right_text"],
        "right_text",
        location,
        allow_recipe=is_versioned,
    )
    _validate_fixture_text(left_text, "left_text", location)
    _validate_fixture_text(right_text, "right_text", location)
    should_link = _require_bool(record["should_link"], "should_link", location)
    return PairExample(
        example_id=_require_identifier(record["id"], "id", location),
        split=split,
        scope=scope,
        left_text=left_text,
        right_text=right_text,
        should_link=should_link,
        observe_only=_require_bool(record["observe_only"], "observe_only", location),
        tags=_require_tags(record["tags"], location),
        rationale=_require_nonempty_string(record["rationale"], "rationale", location),
        family=(
            _require_identifier(record["family"], "family", location)
            if is_versioned
            else "v1_pair"
        ),
        counterfactual_group=(
            _require_optional_identifier(
                record["counterfactual_group"],
                "counterfactual_group",
                location,
            )
            if is_versioned
            else None
        ),
        source_binding_signal=_parse_source_binding_signal(
            record.get("source_binding_signal", "not_applicable"),
            scope=scope,
            location=location,
            required=schema_version == V21_DATASET_SCHEMA_VERSION,
        ),
    )


def _parse_scenario(
    record: dict[str, Any],
    path: Path,
    line_no: int,
    *,
    schema_version: int,
    dataset_version: str,
) -> LineageScenario:
    location = f"{path}:{line_no}"
    is_versioned = schema_version >= V2_DATASET_SCHEMA_VERSION
    _require_exact_keys(
        record,
        (
            _V21_SCENARIO_KEYS
            if schema_version == V21_DATASET_SCHEMA_VERSION
            else (_V2_SCENARIO_KEYS if is_versioned else _V1_SCENARIO_KEYS)
        ),
        location,
    )
    _require_version(
        record,
        location,
        schema_version=schema_version,
        dataset_version=dataset_version,
    )
    _require_synthetic_provenance(record, location)
    split = _require_choice(record["split"], "split", SUPPORTED_SPLITS, location)
    source_text = _require_nonempty_string(record["source_text"], "source_text", location)
    _validate_fixture_text(source_text, "source_text", location)
    artifact_texts = record["artifact_texts"]
    if not isinstance(artifact_texts, list) or not 1 <= len(artifact_texts) <= 8:
        raise SimilarityDatasetError(
            f"{location}: artifact_texts must contain between 1 and 8 strings"
        )
    parsed_artifacts: list[str] = []
    for index, value in enumerate(artifact_texts):
        text = _require_nonempty_string(value, f"artifact_texts[{index}]", location)
        _validate_fixture_text(text, f"artifact_texts[{index}]", location)
        parsed_artifacts.append(text)

    sink_type = _require_choice(
        record["sink_type"],
        "sink_type",
        SUPPORTED_SINK_TYPES,
        location,
    )
    should_reach = _require_bool(
        record["should_reach_sink"],
        "should_reach_sink",
        location,
    )
    expected_action = _require_choice(
        record["expected_action"],
        "expected_action",
        SUPPORTED_ACTIONS,
        location,
    )
    if not should_reach and expected_action != "allow":
        raise SimilarityDatasetError(
            f"{location}: an unreachable sink must have expected_action=allow"
        )
    if sink_type == "final_answer" and expected_action == "block":
        raise SimilarityDatasetError(
            f"{location}: final_answer cannot have expected_action=block"
        )
    if sink_type != "final_answer" and expected_action == "continue_review":
        raise SimilarityDatasetError(
            f"{location}: continue_review is reserved for final_answer"
        )
    return LineageScenario(
        scenario_id=_require_identifier(record["id"], "id", location),
        split=split,
        source_text=source_text,
        artifact_texts=tuple(parsed_artifacts),
        sink_type=sink_type,
        should_reach_sink=should_reach,
        expected_action=expected_action,
        observe_only=_require_bool(record["observe_only"], "observe_only", location),
        tags=_require_tags(record["tags"], location),
        rationale=_require_nonempty_string(record["rationale"], "rationale", location),
        family=(
            _require_identifier(record["family"], "family", location)
            if is_versioned
            else "v1_scenario"
        ),
        counterfactual_group=(
            _require_optional_identifier(
                record["counterfactual_group"],
                "counterfactual_group",
                location,
            )
            if is_versioned
            else None
        ),
        source_binding_signal=_parse_source_binding_signal(
            record.get("source_binding_signal", "registered_source"),
            scope="source_binding",
            location=location,
            required=schema_version == V21_DATASET_SCHEMA_VERSION,
        ),
    )


def _parse_retrieval_pool(
    record: dict[str, Any],
    path: Path,
    line_no: int,
    *,
    schema_version: int,
    dataset_version: str,
) -> RetrievalPool:
    location = f"{path}:{line_no}"
    _require_exact_keys(
        record,
        (
            _V21_RETRIEVAL_POOL_KEYS
            if schema_version == V21_DATASET_SCHEMA_VERSION
            else _RETRIEVAL_POOL_KEYS
        ),
        location,
    )
    _require_version(
        record,
        location,
        schema_version=schema_version,
        dataset_version=dataset_version,
    )
    _require_synthetic_provenance(record, location)
    split = _require_choice(record["split"], "split", SUPPORTED_SPLITS, location)
    scope = _require_choice(
        record["scope"], "scope", SUPPORTED_PAIR_SCOPES, location
    )
    query_text = _require_nonempty_string(
        record["query_text"], "query_text", location
    )
    _validate_fixture_text(query_text, "query_text", location)
    relevant_candidate_id = _require_identifier(
        record["relevant_candidate_id"],
        "relevant_candidate_id",
        location,
    )
    raw_candidates = record["candidates"]
    candidates = _parse_retrieval_candidates(
        raw_candidates,
        location,
        relevant_candidate_id=relevant_candidate_id,
        maximum_candidate_count=(
            _V21_MAX_RETRIEVAL_CANDIDATES
            if schema_version == V21_DATASET_SCHEMA_VERSION
            else _V2_MAX_RETRIEVAL_CANDIDATES
        ),
    )
    candidate_ids = [item.candidate_id for item in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise SimilarityDatasetError(
            f"{location}: retrieval candidate ids must be unique"
        )
    if relevant_candidate_id not in candidate_ids:
        raise SimilarityDatasetError(
            f"{location}: relevant_candidate_id is not in candidates"
        )
    return RetrievalPool(
        pool_id=_require_identifier(record["id"], "id", location),
        split=split,
        scope=scope,
        family=_require_identifier(record["family"], "family", location),
        counterfactual_group=_require_optional_identifier(
            record["counterfactual_group"],
            "counterfactual_group",
            location,
        ),
        query_text=query_text,
        relevant_candidate_id=relevant_candidate_id,
        candidates=candidates,
        observe_only=_require_bool(record["observe_only"], "observe_only", location),
        tags=_require_tags(record["tags"], location),
        rationale=_require_nonempty_string(
            record["rationale"], "rationale", location
        ),
        source_binding_signal=_parse_source_binding_signal(
            record.get("source_binding_signal", "not_applicable"),
            scope=scope,
            location=location,
            required=schema_version == V21_DATASET_SCHEMA_VERSION,
        ),
    )


def _validate_dataset_coverage(
    pairs: tuple[PairExample, ...],
    scenarios: tuple[LineageScenario, ...],
) -> None:
    for split in SUPPORTED_SPLITS:
        split_pairs = [item for item in pairs if item.split == split]
        split_scenarios = [item for item in scenarios if item.split == split]
        if not split_pairs or not split_scenarios:
            raise SimilarityDatasetError(f"dataset split {split} must contain pairs and scenarios")
        for scope in SUPPORTED_PAIR_SCOPES:
            labels = {
                item.should_link for item in split_pairs if item.scope == scope
            }
            if labels != {False, True}:
                raise SimilarityDatasetError(
                    f"dataset split {split} scope {scope} must contain both labels"
                )
        reachability = {item.should_reach_sink for item in split_scenarios}
        if reachability != {False, True}:
            raise SimilarityDatasetError(
                f"dataset split {split} must contain reachable and unreachable scenarios"
            )


def _parse_retrieval_candidates(
    value: Any,
    location: str,
    *,
    relevant_candidate_id: str,
    maximum_candidate_count: int,
) -> tuple[RetrievalPoolCandidate, ...]:
    if isinstance(value, dict):
        if set(value) == _RETRIEVAL_CONSTANT_DECOY_SERIES_KEYS:
            return _parse_constant_decoy_candidate_series(
                value,
                location,
                relevant_candidate_id=relevant_candidate_id,
                maximum_candidate_count=maximum_candidate_count,
            )
        _require_exact_keys(
            value,
            _RETRIEVAL_CANDIDATE_SERIES_KEYS,
            f"{location}.candidates",
        )
        id_prefix = _require_identifier(
            value["id_prefix"],
            "id_prefix",
            f"{location}.candidates",
        )
        decoy_text_prefix = _require_nonempty_string(
            value["decoy_text_prefix"],
            "decoy_text_prefix",
            f"{location}.candidates",
        )
        relevant_text = _require_nonempty_string(
            value["relevant_text"],
            "relevant_text",
            f"{location}.candidates",
        )
        _validate_fixture_text(
            decoy_text_prefix,
            "decoy_text_prefix",
            f"{location}.candidates",
        )
        _validate_fixture_text(
            relevant_text,
            "relevant_text",
            f"{location}.candidates",
        )
        count = value["count"]
        if type(count) is not int or not 1 <= count <= maximum_candidate_count:
            raise SimilarityDatasetError(
                f"{location}.candidates: count must be between 1 and "
                f"{maximum_candidate_count}"
            )
        width = max(3, len(str(count - 1)))
        maximum_decoy_length = len(decoy_text_prefix) + width
        maximum_candidate_length = max(
            maximum_decoy_length,
            len(relevant_text),
        )
        if maximum_candidate_length > _MAX_EXPANDED_FIXTURE_TEXT_CHARS:
            raise SimilarityDatasetError(
                f"{location}.candidates: expanded candidate text is too large"
            )
        if count * maximum_candidate_length > _MAX_RETRIEVAL_POOL_TEXT_CHARS:
            raise SimilarityDatasetError(
                f"{location}.candidates: expanded candidate pool is too large"
            )
        expanded = tuple(
            RetrievalPoolCandidate(
                candidate_id=f"{id_prefix}-{index:0{width}d}",
                text=(
                    relevant_text
                    if f"{id_prefix}-{index:0{width}d}" == relevant_candidate_id
                    else f"{decoy_text_prefix}{index:0{width}d}"
                ),
                sequence_no=index + 1,
            )
            for index in range(count)
        )
        return expanded
    if not isinstance(value, list) or not value:
        raise SimilarityDatasetError(
            f"{location}: candidates must be a non-empty list or series object"
        )
    candidates: list[RetrievalPoolCandidate] = []
    for index, raw_candidate in enumerate(value):
        candidate_location = f"{location}.candidates[{index}]"
        if not isinstance(raw_candidate, dict):
            raise SimilarityDatasetError(
                f"{candidate_location}: candidate must be an object"
            )
        _require_exact_keys(
            raw_candidate,
            _RETRIEVAL_CANDIDATE_KEYS,
            candidate_location,
        )
        text = _require_nonempty_string(
            raw_candidate["text"], "text", candidate_location
        )
        _validate_fixture_text(text, "text", candidate_location)
        sequence_no = raw_candidate["sequence_no"]
        if type(sequence_no) is not int or sequence_no < 1:
            raise SimilarityDatasetError(
                f"{candidate_location}: sequence_no must be a positive integer"
            )
        candidates.append(
            RetrievalPoolCandidate(
                candidate_id=_require_identifier(
                    raw_candidate["id"], "id", candidate_location
                ),
                text=text,
                sequence_no=sequence_no,
            )
        )
    if sum(len(item.text) for item in candidates) > _MAX_RETRIEVAL_POOL_TEXT_CHARS:
        raise SimilarityDatasetError(
            f"{location}.candidates: candidate pool text is too large"
        )
    return tuple(candidates)


def _parse_constant_decoy_candidate_series(
    value: dict[str, Any],
    location: str,
    *,
    relevant_candidate_id: str,
    maximum_candidate_count: int,
) -> tuple[RetrievalPoolCandidate, ...]:
    series_location = f"{location}.candidates"
    id_prefix = _require_identifier(
        value["id_prefix"],
        "id_prefix",
        series_location,
    )
    matching_decoy_text = _require_nonempty_string(
        value["matching_decoy_text"],
        "matching_decoy_text",
        series_location,
    )
    filler_text_prefix = _require_nonempty_string(
        value["filler_text_prefix"],
        "filler_text_prefix",
        series_location,
    )
    relevant_text = _require_nonempty_string(
        value["relevant_text"],
        "relevant_text",
        series_location,
    )
    for field, text in (
        ("matching_decoy_text", matching_decoy_text),
        ("filler_text_prefix", filler_text_prefix),
        ("relevant_text", relevant_text),
    ):
        _validate_fixture_text(text, field, series_location)
    count = value["count"]
    if type(count) is not int or not 1 <= count <= maximum_candidate_count:
        raise SimilarityDatasetError(
            f"{series_location}: count must be between 1 and "
            f"{maximum_candidate_count}"
        )
    matching_decoy_count = value["matching_decoy_count"]
    if (
        type(matching_decoy_count) is not int
        or not 0 <= matching_decoy_count < count
    ):
        raise SimilarityDatasetError(
            f"{series_location}: matching_decoy_count must be between zero "
            "and count - 1"
        )
    width = max(3, len(str(count - 1)))
    maximum_candidate_length = max(
        len(matching_decoy_text),
        len(filler_text_prefix) + width,
        len(relevant_text),
    )
    if maximum_candidate_length > _MAX_EXPANDED_FIXTURE_TEXT_CHARS:
        raise SimilarityDatasetError(
            f"{series_location}: expanded candidate text is too large"
        )
    if count * maximum_candidate_length > _MAX_RETRIEVAL_POOL_TEXT_CHARS:
        raise SimilarityDatasetError(
            f"{series_location}: expanded candidate pool is too large"
        )
    expanded: list[RetrievalPoolCandidate] = []
    for index in range(count):
        candidate_id = f"{id_prefix}-{index:0{width}d}"
        if candidate_id == relevant_candidate_id:
            text = relevant_text
        elif index < matching_decoy_count:
            text = matching_decoy_text
        else:
            text = f"{filler_text_prefix}{index:0{width}d}"
        expanded.append(
            RetrievalPoolCandidate(
                candidate_id=candidate_id,
                text=text,
                sequence_no=index + 1,
            )
        )
    return tuple(expanded)


def _parse_fixture_text(
    value: Any,
    field: str,
    location: object,
    *,
    allow_recipe: bool,
) -> str:
    if isinstance(value, str):
        return _require_nonempty_string(value, field, location)
    if not allow_recipe or not isinstance(value, dict):
        raise SimilarityDatasetError(
            f"{location}: {field} must be a non-empty string"
        )
    recipe_location = f"{location}.{field}"
    _require_exact_keys(value, _TEXT_RECIPE_KEYS, recipe_location)
    head = _require_nonempty_string(value["head"], "head", recipe_location)
    middle = _require_nonempty_string(
        value["middle"], "middle", recipe_location
    )
    tail = _require_nonempty_string(value["tail"], "tail", recipe_location)
    head_count = value["head_count"]
    tail_count = value["tail_count"]
    if (
        type(head_count) is not int
        or type(tail_count) is not int
        or not 1 <= head_count <= 65_536
        or not 1 <= tail_count <= 65_536
    ):
        raise SimilarityDatasetError(
            f"{recipe_location}: repeat counts must be between 1 and 65536"
        )
    expanded_length = (
        (len(head) * head_count)
        + len(middle)
        + (len(tail) * tail_count)
    )
    if expanded_length > _MAX_EXPANDED_FIXTURE_TEXT_CHARS:
        raise SimilarityDatasetError(
            f"{recipe_location}: expanded text exceeds 65536 characters"
        )
    return (head * head_count) + middle + (tail * tail_count)


def _parse_expected_counts(value: Any, location: object) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != _EXPECTED_COUNT_KEYS:
        raise SimilarityDatasetError(
            f"{location}: expected_counts keys are invalid"
        )
    result: dict[str, int] = {}
    for key, raw_count in value.items():
        if type(raw_count) is not int or raw_count < 1:
            raise SimilarityDatasetError(
                f"{location}: expected_counts.{key} must be positive"
            )
        result[key] = raw_count
    return result


def _parse_thresholds(value: Any, location: object) -> dict[str, float]:
    if not isinstance(value, dict) or set(value) != _GO_NO_GO_KEYS:
        raise SimilarityDatasetError(f"{location}: go_no_go keys are invalid")
    result: dict[str, float] = {}
    for key, raw_threshold in value.items():
        if (
            isinstance(raw_threshold, bool)
            or not isinstance(raw_threshold, (int, float))
            or not 0.0 <= float(raw_threshold) <= 1.0
        ):
            raise SimilarityDatasetError(
                f"{location}: go_no_go.{key} must be between zero and one"
            )
        result[key] = float(raw_threshold)
    return result


def _parse_source_binding_signal(
    value: Any,
    *,
    scope: str,
    location: object,
    required: bool,
) -> str:
    signal = _require_choice(
        value,
        "source_binding_signal",
        SUPPORTED_SOURCE_BINDING_SIGNALS,
        location,
    )
    if scope == "artifact_flow" and signal != "not_applicable":
        raise SimilarityDatasetError(
            f"{location}: artifact_flow requires "
            "source_binding_signal=not_applicable"
        )
    if scope == "source_binding" and signal == "not_applicable":
        if required:
            raise SimilarityDatasetError(
                f"{location}: source_binding requires an explicit source signal"
            )
        return "registered_source"
    return signal


def _parse_stress_contract(value: Any, location: object) -> dict[str, object]:
    contract_location = f"{location}.stress_contract"
    if not isinstance(value, dict) or set(value) != _STRESS_CONTRACT_KEYS:
        raise SimilarityDatasetError(
            f"{contract_location}: stress contract keys are invalid"
        )
    raw_sizes = value["generated_pool_sizes"]
    if (
        not isinstance(raw_sizes, list)
        or not raw_sizes
        or any(type(item) is not int for item in raw_sizes)
        or raw_sizes != sorted(set(raw_sizes))
        or raw_sizes[0] < 1_000
        or raw_sizes[-1] > _V21_MAX_RETRIEVAL_CANDIDATES
    ):
        raise SimilarityDatasetError(
            f"{contract_location}.generated_pool_sizes must be sorted unique "
            "integers between 1000 and 10000"
        )
    maximum = value["maximum_candidate_count"]
    if maximum != _V21_MAX_RETRIEVAL_CANDIDATES:
        raise SimilarityDatasetError(
            f"{contract_location}.maximum_candidate_count must be 10000"
        )
    minimum_rate = value["minimum_saturation_rate"]
    if (
        isinstance(minimum_rate, bool)
        or not isinstance(minimum_rate, (int, float))
        or not 0.0 <= float(minimum_rate) <= 1.0
    ):
        raise SimilarityDatasetError(
            f"{contract_location}.minimum_saturation_rate must be between zero and one"
        )
    return {
        "generated_pool_sizes": tuple(raw_sizes),
        "maximum_candidate_count": maximum,
        "minimum_saturation_rate": float(minimum_rate),
    }


def _validate_v21_stress_contract(
    retrieval_pools: tuple[RetrievalPool, ...],
    *,
    stress_contract: dict[str, object],
    location: object,
) -> None:
    declared_sizes = stress_contract["generated_pool_sizes"]
    minimum_rate = stress_contract["minimum_saturation_rate"]
    assert isinstance(declared_sizes, tuple)
    assert isinstance(minimum_rate, float)
    for split in SUPPORTED_SPLITS:
        split_pools = [item for item in retrieval_pools if item.split == split]
        observed_sizes = {len(item.candidates) for item in split_pools}
        missing_sizes = sorted(set(declared_sizes) - observed_sizes)
        if missing_sizes:
            raise SimilarityDatasetError(
                f"{location}: {split} is missing generated pool sizes "
                f"{missing_sizes}"
            )
        saturated = sum(
            len(item.candidates)
            > (
                50 if item.scope == "artifact_flow" else 200
            )
            for item in split_pools
        )
        saturation_rate = saturated / len(split_pools) if split_pools else 0.0
        if saturation_rate < minimum_rate:
            raise SimilarityDatasetError(
                f"{location}: {split} saturation rate is below stress contract"
            )


def _parse_baselines(
    value: Any,
    location: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {"all", *SUPPORTED_SPLITS}:
        raise SimilarityDatasetError(
            f"{location}: baselines must contain all, development, and validation"
        )
    parsed: dict[str, dict[str, object]] = {}
    for split, raw_baseline in value.items():
        baseline_location = f"{location}.baselines.{split}"
        if not isinstance(raw_baseline, dict) or set(raw_baseline) != _BASELINE_KEYS:
            raise SimilarityDatasetError(
                f"{baseline_location}: baseline keys are invalid"
            )
        baseline: dict[str, object] = {}
        for key, item in raw_baseline.items():
            if key.endswith("_sha256"):
                if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None:
                    raise SimilarityDatasetError(
                        f"{baseline_location}.{key} must be a SHA-256 digest"
                    )
            elif type(item) is not int or item < 0:
                raise SimilarityDatasetError(
                    f"{baseline_location}.{key} must be a non-negative integer"
                )
            baseline[key] = item
        parsed[str(split)] = baseline
    return parsed


def _parse_family_contract(value: Any, location: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _FAMILY_CONTRACT_KEYS:
        raise SimilarityDatasetError(
            f"{location}: family_contract keys are invalid"
        )
    result: dict[str, object] = {}
    for layer in ("pair_families", "candidate_families", "scenario_families"):
        raw_split_map = value[layer]
        if not isinstance(raw_split_map, dict) or set(raw_split_map) != _SPLIT_MAP_KEYS:
            raise SimilarityDatasetError(
                f"{location}: family_contract.{layer} split map is invalid"
            )
        parsed_split_map: dict[str, tuple[str, ...]] = {}
        for split, raw_families in raw_split_map.items():
            if not isinstance(raw_families, list) or not raw_families:
                raise SimilarityDatasetError(
                    f"{location}: {layer}.{split} must be a non-empty list"
                )
            families = tuple(
                _require_identifier(item, layer, location)
                for item in raw_families
            )
            if list(families) != sorted(set(families)):
                raise SimilarityDatasetError(
                    f"{location}: {layer}.{split} must be sorted and unique"
                )
            parsed_split_map[str(split)] = families
        if set(parsed_split_map["development"]) & set(
            parsed_split_map["validation"]
        ):
            raise SimilarityDatasetError(
                f"{location}: {layer} development and validation must be non-mirror"
            )
        result[layer] = parsed_split_map
    for key, floor in (
        ("counterfactual_groups_per_split", 1),
        ("minimum_artifact_pool_size", 51),
        ("minimum_source_pool_size", 201),
    ):
        raw_value = value[key]
        if type(raw_value) is not int or raw_value < floor:
            raise SimilarityDatasetError(
                f"{location}: family_contract.{key} must be at least {floor}"
            )
        result[key] = raw_value
    for key in (
        "maximum_split_vocabulary_jaccard",
        "maximum_split_feature_jaccard",
    ):
        raw_value = value[key]
        if (
            isinstance(raw_value, bool)
            or not isinstance(raw_value, (int, float))
            or not 0.0 <= float(raw_value) <= 1.0
        ):
            raise SimilarityDatasetError(
                f"{location}: family_contract.{key} must be between zero and one"
            )
        result[key] = float(raw_value)
    for split in SUPPORTED_SPLITS:
        key = f"{split}_shape_sha256"
        raw_value = value[key]
        if not isinstance(raw_value, str) or re.fullmatch(
            r"[0-9a-f]{64}", raw_value
        ) is None:
            raise SimilarityDatasetError(
                f"{location}: family_contract.{key} must be a SHA-256 digest"
            )
        result[key] = raw_value
    return result


def _validate_v2_contract(
    pairs: tuple[PairExample, ...],
    scenarios: tuple[LineageScenario, ...],
    retrieval_pools: tuple[RetrievalPool, ...],
    *,
    expected_counts: dict[str, int],
    family_contract: dict[str, object],
    location: object,
) -> dict[str, object]:
    observed_counts = {
        "pairs": len(pairs),
        "scenarios": len(scenarios),
        "retrieval_pools": len(retrieval_pools),
        "development_pairs": sum(item.split == "development" for item in pairs),
        "validation_pairs": sum(item.split == "validation" for item in pairs),
        "development_scenarios": sum(
            item.split == "development" for item in scenarios
        ),
        "validation_scenarios": sum(
            item.split == "validation" for item in scenarios
        ),
        "development_retrieval_pools": sum(
            item.split == "development" for item in retrieval_pools
        ),
        "validation_retrieval_pools": sum(
            item.split == "validation" for item in retrieval_pools
        ),
        "development_gate_pairs": sum(
            item.split == "development" and not item.observe_only for item in pairs
        ),
        "validation_gate_pairs": sum(
            item.split == "validation" and not item.observe_only for item in pairs
        ),
        "development_gate_scenarios": sum(
            item.split == "development" and not item.observe_only
            for item in scenarios
        ),
        "validation_gate_scenarios": sum(
            item.split == "validation" and not item.observe_only
            for item in scenarios
        ),
        "development_gate_retrieval_pools": sum(
            item.split == "development" and not item.observe_only
            for item in retrieval_pools
        ),
        "validation_gate_retrieval_pools": sum(
            item.split == "validation" and not item.observe_only
            for item in retrieval_pools
        ),
    }
    if observed_counts != expected_counts:
        raise SimilarityDatasetError(
            f"{location}: expected_counts do not match fixture records"
        )
    for layer, records in (
        ("pair_families", pairs),
        ("candidate_families", retrieval_pools),
        ("scenario_families", scenarios),
    ):
        expected_by_split = family_contract[layer]
        assert isinstance(expected_by_split, dict)
        for split in SUPPORTED_SPLITS:
            observed = tuple(
                sorted({item.family for item in records if item.split == split})
            )
            if observed != expected_by_split[split]:
                raise SimilarityDatasetError(
                    f"{location}: {layer}.{split} does not match fixture families"
                )
    groups_by_split: dict[str, dict[str, list[object]]] = {
        split: {} for split in SUPPORTED_SPLITS
    }
    for item in (*pairs, *retrieval_pools, *scenarios):
        group = item.counterfactual_group
        if group is not None:
            groups_by_split[item.split].setdefault(group, []).append(item)
    expected_groups = family_contract["counterfactual_groups_per_split"]
    assert isinstance(expected_groups, int)
    for split, groups in groups_by_split.items():
        if len(groups) != expected_groups:
            raise SimilarityDatasetError(
                f"{location}: {split} counterfactual group count is invalid"
            )
        for group, items in groups.items():
            _validate_counterfactual_group(group, items, location)
    artifact_floor = family_contract["minimum_artifact_pool_size"]
    source_floor = family_contract["minimum_source_pool_size"]
    assert isinstance(artifact_floor, int) and isinstance(source_floor, int)
    for split in SUPPORTED_SPLITS:
        for scope, floor in (
            ("artifact_flow", artifact_floor),
            ("source_binding", source_floor),
        ):
            sizes = [
                len(item.candidates)
                for item in retrieval_pools
                if item.split == split and item.scope == scope
            ]
            if not sizes or max(sizes) < floor:
                raise SimilarityDatasetError(
                    f"{location}: {split} {scope} does not saturate its cap"
                )
    split_contract = _split_contract_metrics(pairs, scenarios, retrieval_pools)
    if split_contract["shared_scored_marker_count"] != 0:
        raise SimilarityDatasetError(
            f"{location}: scored texts contain a shared non-stop marker"
        )
    for metric, maximum_key in (
        ("split_vocabulary_jaccard", "maximum_split_vocabulary_jaccard"),
        ("split_feature_jaccard", "maximum_split_feature_jaccard"),
    ):
        maximum = family_contract[maximum_key]
        assert isinstance(maximum, float)
        if split_contract[metric] > maximum:
            raise SimilarityDatasetError(
                f"{location}: {metric} exceeds family contract"
            )
    observed_shapes = {
        split: split_contract[f"{split}_shape_sha256"]
        for split in SUPPORTED_SPLITS
    }
    expected_shapes = {
        split: family_contract[f"{split}_shape_sha256"]
        for split in SUPPORTED_SPLITS
    }
    if len(set(observed_shapes.values())) != 2:
        raise SimilarityDatasetError(
            f"{location}: development and validation shape digests must differ"
        )
    if observed_shapes != expected_shapes:
        raise SimilarityDatasetError(
            f"{location}: shape digest mismatch; observed={observed_shapes}"
        )
    return split_contract


def _split_contract_metrics(
    pairs: tuple[PairExample, ...],
    scenarios: tuple[LineageScenario, ...],
    retrieval_pools: tuple[RetrievalPool, ...],
) -> dict[str, object]:
    texts_by_split = {
        split: _scored_texts_for_split(
            split,
            pairs,
            scenarios,
            retrieval_pools,
        )
        for split in SUPPORTED_SPLITS
    }
    vocabulary = {
        split: set().union(*(_derived_tokens(text) for text in texts))
        if texts
        else set()
        for split, texts in texts_by_split.items()
    }
    features = {
        split: set().union(*(_derived_features(text) for text in texts))
        if texts
        else set()
        for split, texts in texts_by_split.items()
    }
    all_scored_texts = tuple(
        text for texts in texts_by_split.values() for text in texts
    )
    shared_markers = (
        set.intersection(*(_derived_tokens(text) for text in all_scored_texts))
        if all_scored_texts
        else set()
    )
    development_shape = _shape_digest(
        "development",
        pairs,
        scenarios,
        retrieval_pools,
    )
    validation_shape = _shape_digest(
        "validation",
        pairs,
        scenarios,
        retrieval_pools,
    )
    return {
        "development_shape_sha256": development_shape,
        "validation_shape_sha256": validation_shape,
        "split_vocabulary_jaccard": _set_jaccard(
            vocabulary["development"],
            vocabulary["validation"],
        ),
        "split_feature_jaccard": _set_jaccard(
            features["development"],
            features["validation"],
        ),
        "shared_scored_marker_count": len(shared_markers),
    }


def _scored_texts_for_split(
    split: str,
    pairs: tuple[PairExample, ...],
    scenarios: tuple[LineageScenario, ...],
    retrieval_pools: tuple[RetrievalPool, ...],
) -> tuple[str, ...]:
    texts: list[str] = []
    for pair in pairs:
        if pair.split == split and not pair.observe_only:
            texts.extend((pair.left_text, pair.right_text))
    for scenario in scenarios:
        if scenario.split == split and not scenario.observe_only:
            texts.append(scenario.source_text)
            texts.extend(scenario.artifact_texts)
    for pool in retrieval_pools:
        if pool.split == split and not pool.observe_only:
            texts.append(pool.query_text)
            texts.extend(candidate.text for candidate in pool.candidates)
    return tuple(texts)


def _derived_tokens(text: str) -> set[str]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return {
        token
        for token in re.findall(r"[^\W_]+", normalized, flags=re.UNICODE)
        if len(token) >= 4 and token not in _SPLIT_CONTRACT_STOP_TOKENS
    }


def _derived_features(text: str) -> set[str]:
    features: set[str] = set()
    for token in _derived_tokens(text):
        if len(token) < 5:
            features.add(token)
            continue
        features.update(
            token[index : index + 5] for index in range(len(token) - 4)
        )
    return features


def _set_jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return round(len(left & right) / len(union), 6) if union else 0.0


def _shape_digest(
    split: str,
    pairs: tuple[PairExample, ...],
    scenarios: tuple[LineageScenario, ...],
    retrieval_pools: tuple[RetrievalPool, ...],
) -> str:
    payload: list[object] = []
    for pair in pairs:
        if pair.split == split:
            payload.append(
                (
                    "pair",
                    pair.scope,
                    pair.should_link,
                    pair.observe_only,
                    _text_shape(pair.left_text),
                    _text_shape(pair.right_text),
                )
            )
    for scenario in scenarios:
        if scenario.split == split:
            payload.append(
                (
                    "scenario",
                    scenario.sink_type,
                    scenario.should_reach_sink,
                    scenario.expected_action,
                    scenario.observe_only,
                    _text_shape(scenario.source_text),
                    tuple(_text_shape(text) for text in scenario.artifact_texts),
                )
            )
    for pool in retrieval_pools:
        if pool.split == split:
            payload.append(
                (
                    "retrieval",
                    pool.scope,
                    pool.observe_only,
                    len(pool.candidates),
                    _text_shape(pool.query_text),
                    tuple(sorted({_text_shape(item.text) for item in pool.candidates})),
                )
            )
    digest = hashlib.sha256(b"tooluseproxy-similarity-shape-v2\0")
    digest.update(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return digest.hexdigest()


def _text_shape(text: str) -> tuple[int, int, int, int, int]:
    return (
        len(text),
        len(text.split()),
        sum(character.isalpha() for character in text),
        sum(character.isdigit() for character in text),
        sum(ord(character) > 127 for character in text),
    )


def _validate_counterfactual_group(
    group: str,
    items: list[object],
    location: object,
) -> None:
    if len(items) != 2 or type(items[0]) is not type(items[1]):
        raise SimilarityDatasetError(
            f"{location}: counterfactual group {group} must contain one typed pair"
        )
    first, second = items
    if isinstance(first, PairExample) and isinstance(second, PairExample):
        if (
            first.scope != second.scope
            or first.family != second.family
            or first.should_link == second.should_link
            or not (
                first.left_text == second.left_text
                or first.right_text == second.right_text
            )
        ):
            raise SimilarityDatasetError(
                f"{location}: pair counterfactual group {group} is invalid"
            )
        return
    if isinstance(first, RetrievalPool) and isinstance(second, RetrievalPool):
        if (
            first.scope != second.scope
            or first.family != second.family
            or first.query_text != second.query_text
            or len(first.candidates) != len(second.candidates)
        ):
            raise SimilarityDatasetError(
                f"{location}: candidate counterfactual group {group} is invalid"
            )
        return
    if isinstance(first, LineageScenario) and isinstance(second, LineageScenario):
        if (
            first.family != second.family
            or first.sink_type != second.sink_type
            or first.should_reach_sink == second.should_reach_sink
        ):
            raise SimilarityDatasetError(
                f"{location}: scenario counterfactual group {group} is invalid"
            )
        return
    raise SimilarityDatasetError(
        f"{location}: counterfactual group {group} has unsupported members"
    )


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SimilarityDatasetError(f"missing similarity dataset file: {path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SimilarityDatasetError(f"cannot read similarity dataset file {path}: {error}") from error
    if not isinstance(value, dict):
        raise SimilarityDatasetError(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise SimilarityDatasetError(f"missing similarity dataset file: {path}") from error
    except (OSError, UnicodeError) as error:
        raise SimilarityDatasetError(f"cannot read similarity dataset file {path}: {error}") from error
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            raise SimilarityDatasetError(f"{path}:{line_no}: blank JSONL lines are not allowed")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise SimilarityDatasetError(f"{path}:{line_no}: invalid JSON: {error.msg}") from error
        if not isinstance(value, dict):
            raise SimilarityDatasetError(f"{path}:{line_no}: expected a JSON object")
        records.append((line_no, value))
    return records


def _resolve_fixture_file(root: Path, value: Any, field: str, location: object) -> Path:
    name = _require_nonempty_string(value, field, location)
    candidate = Path(name)
    if candidate.is_absolute() or len(candidate.parts) != 1 or candidate.name != name:
        raise SimilarityDatasetError(f"{location}: {field} must be a local file name")
    return root / candidate


def _require_version(
    record: dict[str, Any],
    location: object,
    *,
    schema_version: int,
    dataset_version: str,
) -> None:
    if record.get("schema_version") != schema_version:
        raise SimilarityDatasetError(
            f"{location}: schema_version must be {schema_version}"
        )
    if record.get("dataset_version") != dataset_version:
        raise SimilarityDatasetError(
            f"{location}: dataset_version must be {dataset_version}"
        )


def _require_exact_keys(
    record: dict[str, Any],
    expected: frozenset[str],
    location: object,
) -> None:
    actual = set(record)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    details = []
    if missing:
        details.append(f"missing={','.join(missing)}")
    if unknown:
        details.append(f"unknown={','.join(unknown)}")
    raise SimilarityDatasetError(f"{location}: invalid fields ({'; '.join(details)})")


def _require_identifier(value: Any, field: str, location: object) -> str:
    text = _require_nonempty_string(value, field, location)
    if not _ID_PATTERN.fullmatch(text):
        raise SimilarityDatasetError(f"{location}: {field} is not a stable identifier")
    return text


def _require_optional_identifier(
    value: Any,
    field: str,
    location: object,
) -> str | None:
    if value is None:
        return None
    return _require_identifier(value, field, location)


def _require_nonempty_string(value: Any, field: str, location: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SimilarityDatasetError(f"{location}: {field} must be a non-empty string")
    return value


def _require_choice(
    value: Any,
    field: str,
    choices: frozenset[str],
    location: object,
) -> str:
    if not isinstance(value, str) or value not in choices:
        raise SimilarityDatasetError(
            f"{location}: {field} must be one of {', '.join(sorted(choices))}"
        )
    return value


def _require_bool(value: Any, field: str, location: object) -> bool:
    if type(value) is not bool:
        raise SimilarityDatasetError(f"{location}: {field} must be boolean")
    return value


def _require_tags(value: Any, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise SimilarityDatasetError(f"{location}: tags must be a non-empty list")
    if any(not isinstance(tag, str) or not _TAG_PATTERN.fullmatch(tag) for tag in value):
        raise SimilarityDatasetError(f"{location}: tags contain an invalid value")
    if value != sorted(set(value)):
        raise SimilarityDatasetError(f"{location}: tags must be sorted and unique")
    return tuple(value)


def _validate_fixture_text(value: str, field: str, location: object) -> None:
    if "\0" in value:
        raise SimilarityDatasetError(f"{location}: {field} contains a null byte")
    for label, pattern in _FORBIDDEN_SECRET_PATTERNS:
        if pattern.search(value):
            raise SimilarityDatasetError(
                f"{location}: {field} resembles a real {label}"
            )


def _require_synthetic_provenance(record: dict[str, Any], location: object) -> None:
    if record.get("provenance") != "synthetic":
        raise SimilarityDatasetError(f"{location}: provenance must be synthetic")


def _validate_requested_split(split: str | None) -> None:
    if split is not None and split not in SUPPORTED_SPLITS:
        raise ValueError(f"unsupported dataset split: {split}")


def _dataset_digest(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
