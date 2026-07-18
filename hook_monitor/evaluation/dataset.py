from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DATASET_SCHEMA_VERSION = 1
SUPPORTED_DATASET_VERSION = "1.0.0"
SUPPORTED_SPLITS = frozenset({"development", "validation"})
SUPPORTED_PAIR_SCOPES = frozenset({"artifact_flow", "source_binding"})
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
_MANIFEST_KEYS = frozenset(
    {"schema_version", "dataset_id", "dataset_version", "description", "files"}
)
_PAIR_KEYS = frozenset(
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
_SCENARIO_KEYS = frozenset(
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


@dataclass(frozen=True)
class SimilarityDataset:
    dataset_id: str
    dataset_version: str
    description: str
    digest_sha256: str
    pairs: tuple[PairExample, ...]
    scenarios: tuple[LineageScenario, ...]

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


def load_similarity_dataset(root: Path) -> SimilarityDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_json_object(manifest_path)
    _require_exact_keys(manifest, _MANIFEST_KEYS, manifest_path)
    _require_version(manifest, manifest_path)

    dataset_id = _require_identifier(manifest["dataset_id"], "dataset_id", manifest_path)
    description = _require_nonempty_string(
        manifest["description"],
        "description",
        manifest_path,
    )
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"pairs", "scenarios"}:
        raise SimilarityDatasetError(
            f"{manifest_path}: files must contain exactly pairs and scenarios"
        )
    pair_path = _resolve_fixture_file(root, files["pairs"], "files.pairs", manifest_path)
    scenario_path = _resolve_fixture_file(
        root,
        files["scenarios"],
        "files.scenarios",
        manifest_path,
    )

    pair_records = _load_jsonl(pair_path)
    scenario_records = _load_jsonl(scenario_path)
    pairs = tuple(_parse_pair(record, pair_path, line_no) for line_no, record in pair_records)
    scenarios = tuple(
        _parse_scenario(record, scenario_path, line_no)
        for line_no, record in scenario_records
    )
    if not pairs:
        raise SimilarityDatasetError(f"{pair_path}: at least one pair is required")
    if not scenarios:
        raise SimilarityDatasetError(f"{scenario_path}: at least one scenario is required")

    all_ids = [item.example_id for item in pairs] + [
        item.scenario_id for item in scenarios
    ]
    duplicates = sorted({item_id for item_id in all_ids if all_ids.count(item_id) > 1})
    if duplicates:
        raise SimilarityDatasetError(
            f"dataset case ids must be unique: {', '.join(duplicates)}"
        )

    _validate_dataset_coverage(pairs, scenarios)
    digest = _dataset_digest((manifest_path, pair_path, scenario_path))
    return SimilarityDataset(
        dataset_id=dataset_id,
        dataset_version=SUPPORTED_DATASET_VERSION,
        description=description,
        digest_sha256=digest,
        pairs=pairs,
        scenarios=scenarios,
    )


def _parse_pair(record: dict[str, Any], path: Path, line_no: int) -> PairExample:
    location = f"{path}:{line_no}"
    _require_exact_keys(record, _PAIR_KEYS, location)
    _require_version(record, location)
    _require_synthetic_provenance(record, location)
    split = _require_choice(record["split"], "split", SUPPORTED_SPLITS, location)
    scope = _require_choice(record["scope"], "scope", SUPPORTED_PAIR_SCOPES, location)
    left_text = _require_nonempty_string(record["left_text"], "left_text", location)
    right_text = _require_nonempty_string(record["right_text"], "right_text", location)
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
    )


def _parse_scenario(
    record: dict[str, Any],
    path: Path,
    line_no: int,
) -> LineageScenario:
    location = f"{path}:{line_no}"
    _require_exact_keys(record, _SCENARIO_KEYS, location)
    _require_version(record, location)
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


def _require_version(record: dict[str, Any], location: object) -> None:
    if record.get("schema_version") != DATASET_SCHEMA_VERSION:
        raise SimilarityDatasetError(
            f"{location}: schema_version must be {DATASET_SCHEMA_VERSION}"
        )
    if record.get("dataset_version") != SUPPORTED_DATASET_VERSION:
        raise SimilarityDatasetError(
            f"{location}: dataset_version must be {SUPPORTED_DATASET_VERSION}"
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
