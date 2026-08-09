from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hook_monitor.evaluation.source_ingestion_dataset import (
    SourceIngestionDataset,
    SourceIngestionDatasetError,
    SourceIngestionScenario,
    load_source_ingestion_dataset,
)


DATASET_SCHEMA_BY_VERSION = {
    "1.0.0": 1,
    "1.1.0": 2,
}
SUPPORTED_SPLITS = frozenset({"development", "validation"})
SOURCE_KINDS = frozenset(
    {
        "credential",
        "structured_secret",
        "private_prose",
        "source_code",
        "decision_material",
    }
)
TRANSFORMATIONS = frozenset(
    {
        "exact_copy",
        "canonical_encoding",
        "substring",
        "paraphrase",
        "file_reference",
        "multi_step",
    }
)
BOUNDARIES = frozenset({"same_turn", "same_session"})
PAYLOAD_VISIBILITIES = frozenset({"inline", "resolvable", "opaque"})
RECOMMENDED_ACTIONS = frozenset({"allow", "block", "continue_review"})

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_version",
        "description",
        "ingestion_dataset",
        "files",
    }
)
_CASE_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "source_kind",
        "transformation",
        "boundary",
        "sink_surface",
        "payload_visibility",
        "is_leak",
        "recommended_action",
        "observe_only",
        "tags",
        "rationale",
    }
)
_CASE_KEYS_V2 = _CASE_KEYS | {"workspace_files"}
_WORKSPACE_FILE_KEYS = frozenset({"path", "content"})
_MAX_WORKSPACE_FILE_BYTES = 32 * 1024
_MAX_WORKSPACE_FILES_TOTAL_BYTES = 128 * 1024
_FORBIDDEN_SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI-style token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


class SinkBenchmarkDatasetError(ValueError):
    """Raised when a sink benchmark fixture violates its public contract."""


@dataclass(frozen=True)
class SinkBenchmarkWorkspaceFile:
    path: str
    content: str


@dataclass(frozen=True)
class SinkBenchmarkCase:
    case_id: str
    split: str
    source_kind: str
    transformation: str
    boundary: str
    sink_surface: str
    payload_visibility: str
    is_leak: bool
    recommended_action: str
    observe_only: bool
    tags: tuple[str, ...]
    rationale: str
    workspace_files: tuple[SinkBenchmarkWorkspaceFile, ...]
    ingestion: SourceIngestionScenario


@dataclass(frozen=True)
class SinkBenchmarkDataset:
    dataset_id: str
    dataset_version: str
    description: str
    digest_sha256: str
    ingestion_dataset: SourceIngestionDataset
    cases: tuple[SinkBenchmarkCase, ...]

    def select_cases(self, split: str | None = None) -> tuple[SinkBenchmarkCase, ...]:
        if split is not None and split not in SUPPORTED_SPLITS:
            raise SinkBenchmarkDatasetError(f"unsupported dataset split: {split}")
        if split is None:
            return self.cases
        return tuple(case for case in self.cases if case.split == split)


def load_sink_benchmark_dataset(root: Path) -> SinkBenchmarkDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_object(manifest_path)
    _require_exact_keys(manifest, _MANIFEST_KEYS, manifest_path)
    dataset_version = _require_version(manifest, manifest_path)
    schema_version = DATASET_SCHEMA_BY_VERSION[dataset_version]
    if manifest["schema_version"] != schema_version:
        raise SinkBenchmarkDatasetError(
            f"{manifest_path}: schema_version must be {schema_version}"
        )
    dataset_id = _require_identifier(manifest["dataset_id"], "dataset_id", manifest_path)
    description = _require_text(manifest["description"], "description", manifest_path)

    ingestion_directory = _resolve_directory(
        root,
        manifest["ingestion_dataset"],
        "ingestion_dataset",
        manifest_path,
    )
    try:
        ingestion_dataset = load_source_ingestion_dataset(ingestion_directory)
    except SourceIngestionDatasetError as error:
        raise SinkBenchmarkDatasetError(
            f"{manifest_path}: invalid ingestion dataset: {error}"
        ) from None
    if ingestion_dataset.dataset_version != "3.0.0":
        raise SinkBenchmarkDatasetError(
            f"{manifest_path}: ingestion dataset must use version 3.0.0"
        )

    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"cases"}:
        raise SinkBenchmarkDatasetError(
            f"{manifest_path}: files must contain exactly cases"
        )
    cases_path = _resolve_file(root, files["cases"], "files.cases", manifest_path)
    records = _load_jsonl(cases_path)
    ingestion_by_id = {
        scenario.scenario_id: scenario for scenario in ingestion_dataset.scenarios
    }
    cases = tuple(
        _parse_case(
            record,
            location=f"{cases_path}:{line_no}",
            dataset_version=dataset_version,
            ingestion_by_id=ingestion_by_id,
        )
        for line_no, record in records
    )
    if not cases:
        raise SinkBenchmarkDatasetError(f"{cases_path}: at least one case is required")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise SinkBenchmarkDatasetError(f"{cases_path}: case ids must be unique")
    if set(case_ids) != set(ingestion_by_id):
        missing = sorted(set(ingestion_by_id) - set(case_ids))
        extra = sorted(set(case_ids) - set(ingestion_by_id))
        raise SinkBenchmarkDatasetError(
            f"{cases_path}: case and ingestion ids differ; "
            f"missing={missing}, extra={extra}"
        )
    _validate_coverage(cases, cases_path)

    digest = hashlib.sha256()
    digest.update(b"sink-benchmark-dataset-v1\0")
    digest.update(manifest_path.read_bytes())
    digest.update(b"\0")
    digest.update(cases_path.read_bytes())
    digest.update(b"\0")
    digest.update(ingestion_dataset.digest_sha256.encode("ascii"))
    return SinkBenchmarkDataset(
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        description=description,
        digest_sha256=digest.hexdigest(),
        ingestion_dataset=ingestion_dataset,
        cases=cases,
    )


def _parse_case(
    value: Any,
    *,
    location: object,
    dataset_version: str,
    ingestion_by_id: dict[str, SourceIngestionScenario],
) -> SinkBenchmarkCase:
    if not isinstance(value, dict):
        raise SinkBenchmarkDatasetError(f"{location}: case must be an object")
    case_keys = (
        _CASE_KEYS_V2
        if DATASET_SCHEMA_BY_VERSION[dataset_version] == 2
        else _CASE_KEYS
    )
    _require_exact_keys(value, case_keys, location)
    if value["schema_version"] != DATASET_SCHEMA_BY_VERSION[dataset_version]:
        raise SinkBenchmarkDatasetError(f"{location}: schema_version mismatch")
    if value["dataset_version"] != dataset_version:
        raise SinkBenchmarkDatasetError(f"{location}: dataset_version mismatch")
    case_id = _require_identifier(value["id"], "id", location)
    ingestion = ingestion_by_id.get(case_id)
    if ingestion is None:
        raise SinkBenchmarkDatasetError(
            f"{location}: no ingestion scenario exists for {case_id}"
        )
    split = _require_choice(value["split"], SUPPORTED_SPLITS, "split", location)
    source_kind = _require_choice(
        value["source_kind"], SOURCE_KINDS, "source_kind", location
    )
    transformation = _require_choice(
        value["transformation"], TRANSFORMATIONS, "transformation", location
    )
    boundary = _require_choice(value["boundary"], BOUNDARIES, "boundary", location)
    sink_surface = _require_text(value["sink_surface"], "sink_surface", location)
    payload_visibility = _require_choice(
        value["payload_visibility"],
        PAYLOAD_VISIBILITIES,
        "payload_visibility",
        location,
    )
    is_leak = _require_bool(value["is_leak"], "is_leak", location)
    recommended_action = _require_choice(
        value["recommended_action"],
        RECOMMENDED_ACTIONS,
        "recommended_action",
        location,
    )
    observe_only = _require_bool(value["observe_only"], "observe_only", location)
    tags = _require_tags(value["tags"], location)
    rationale = _require_text(value["rationale"], "rationale", location)
    workspace_files = _parse_workspace_files(
        value.get("workspace_files", []),
        location,
        source_path=ingestion.source.path,
    )

    if split != ingestion.split:
        raise SinkBenchmarkDatasetError(f"{location}: split differs from ingestion case")
    if sink_surface != ingestion.expected_sink_type:
        raise SinkBenchmarkDatasetError(
            f"{location}: sink_surface differs from ingestion case"
        )
    if is_leak != ingestion.should_reach_sink:
        raise SinkBenchmarkDatasetError(
            f"{location}: is_leak differs from ingestion ground truth"
        )
    if recommended_action != ingestion.expected_action:
        raise SinkBenchmarkDatasetError(
            f"{location}: recommended_action differs from ingestion ground truth"
        )
    if observe_only != ingestion.observe_only:
        raise SinkBenchmarkDatasetError(
            f"{location}: observe_only differs from ingestion case"
        )
    if not is_leak and recommended_action != "allow":
        raise SinkBenchmarkDatasetError(
            f"{location}: non-leak cases must recommend allow"
        )

    return SinkBenchmarkCase(
        case_id=case_id,
        split=split,
        source_kind=source_kind,
        transformation=transformation,
        boundary=boundary,
        sink_surface=sink_surface,
        payload_visibility=payload_visibility,
        is_leak=is_leak,
        recommended_action=recommended_action,
        observe_only=observe_only,
        tags=tags,
        rationale=rationale,
        workspace_files=workspace_files,
        ingestion=ingestion,
    )


def _parse_workspace_files(
    value: Any,
    location: object,
    *,
    source_path: str,
) -> tuple[SinkBenchmarkWorkspaceFile, ...]:
    if not isinstance(value, list):
        raise SinkBenchmarkDatasetError(
            f"{location}: workspace_files must be a list"
        )
    files: list[SinkBenchmarkWorkspaceFile] = []
    total_bytes = 0
    for index, item in enumerate(value):
        item_location = f"{location}.workspace_files[{index}]"
        if not isinstance(item, dict):
            raise SinkBenchmarkDatasetError(
                f"{item_location}: workspace file must be an object"
            )
        _require_exact_keys(item, _WORKSPACE_FILE_KEYS, item_location)
        relative_path = _require_relative_path(
            item["path"],
            "path",
            item_location,
        )
        if relative_path == Path("."):
            raise SinkBenchmarkDatasetError(
                f"{item_location}: workspace file path must name a file"
            )
        path_text = relative_path.as_posix()
        if path_text == source_path:
            raise SinkBenchmarkDatasetError(
                f"{item_location}: workspace file must not replace source"
            )
        content = _require_text(item["content"], "content", item_location)
        for label, pattern in _FORBIDDEN_SECRET_PATTERNS:
            if pattern.search(content):
                raise SinkBenchmarkDatasetError(
                    f"{item_location}: workspace file matches forbidden {label}"
                )
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > _MAX_WORKSPACE_FILE_BYTES:
            raise SinkBenchmarkDatasetError(
                f"{item_location}: workspace file exceeds byte limit"
            )
        total_bytes += content_bytes
        if total_bytes > _MAX_WORKSPACE_FILES_TOTAL_BYTES:
            raise SinkBenchmarkDatasetError(
                f"{location}: workspace files exceed total byte limit"
            )
        files.append(
            SinkBenchmarkWorkspaceFile(
                path=path_text,
                content=content,
            )
        )
    paths = [item.path for item in files]
    if len(paths) != len(set(paths)):
        raise SinkBenchmarkDatasetError(
            f"{location}: workspace file paths must be unique"
        )
    all_paths = [Path(source_path), *(Path(path) for path in paths)]
    if any(
        left in right.parents or right in left.parents
        for index, left in enumerate(all_paths)
        for right in all_paths[index + 1 :]
    ):
        raise SinkBenchmarkDatasetError(
            f"{location}: workspace file paths must not overlap"
        )
    return tuple(files)


def _validate_coverage(cases: tuple[SinkBenchmarkCase, ...], location: Path) -> None:
    for split in SUPPORTED_SPLITS:
        selected = [case for case in cases if case.split == split]
        if not selected:
            raise SinkBenchmarkDatasetError(f"{location}: split {split} is empty")
        if {case.is_leak for case in selected} != {False, True}:
            raise SinkBenchmarkDatasetError(
                f"{location}: split {split} must contain leak and non-leak cases"
            )


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SinkBenchmarkDatasetError(
            f"missing sink benchmark dataset file: {path}"
        ) from None
    except json.JSONDecodeError as error:
        raise SinkBenchmarkDatasetError(f"{path}: invalid JSON: {error.msg}") from None
    if not isinstance(value, dict):
        raise SinkBenchmarkDatasetError(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise SinkBenchmarkDatasetError(
            f"missing sink benchmark dataset file: {path}"
        ) from None
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise SinkBenchmarkDatasetError(
                f"{path}:{line_no}: invalid JSON: {error.msg}"
            ) from None
        if not isinstance(value, dict):
            raise SinkBenchmarkDatasetError(
                f"{path}:{line_no}: expected a JSON object"
            )
        records.append((line_no, value))
    return records


def _resolve_directory(root: Path, value: Any, field: str, location: object) -> Path:
    relative = _require_relative_path(value, field, location)
    resolved = root / relative
    if not resolved.is_dir():
        raise SinkBenchmarkDatasetError(f"{location}: {field} is not a directory")
    return resolved


def _resolve_file(root: Path, value: Any, field: str, location: object) -> Path:
    relative = _require_relative_path(value, field, location)
    resolved = root / relative
    if not resolved.is_file():
        raise SinkBenchmarkDatasetError(f"{location}: {field} is not a file")
    return resolved


def _require_relative_path(value: Any, field: str, location: object) -> Path:
    text = _require_text(value, field, location)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise SinkBenchmarkDatasetError(
            f"{location}: {field} must be a contained relative path"
        )
    return path


def _require_exact_keys(value: dict[str, Any], expected: frozenset[str], location: object) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SinkBenchmarkDatasetError(
            f"{location}: object keys differ; missing={missing}, extra={extra}"
        )


def _require_version(value: dict[str, Any], location: object) -> str:
    version = value["dataset_version"]
    if version not in DATASET_SCHEMA_BY_VERSION:
        raise SinkBenchmarkDatasetError(f"{location}: unsupported dataset_version")
    return str(version)


def _require_identifier(value: Any, field: str, location: object) -> str:
    text = _require_text(value, field, location)
    if _ID_PATTERN.fullmatch(text) is None:
        raise SinkBenchmarkDatasetError(f"{location}: {field} is invalid")
    return text


def _require_text(value: Any, field: str, location: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SinkBenchmarkDatasetError(f"{location}: {field} must be non-empty text")
    return value


def _require_choice(
    value: Any,
    choices: frozenset[str],
    field: str,
    location: object,
) -> str:
    text = _require_text(value, field, location)
    if text not in choices:
        raise SinkBenchmarkDatasetError(f"{location}: {field} is unsupported")
    return text


def _require_bool(value: Any, field: str, location: object) -> bool:
    if not isinstance(value, bool):
        raise SinkBenchmarkDatasetError(f"{location}: {field} must be boolean")
    return value


def _require_tags(value: Any, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise SinkBenchmarkDatasetError(f"{location}: tags must be a non-empty list")
    tags = tuple(_require_text(item, "tag", location) for item in value)
    if len(tags) != len(set(tags)):
        raise SinkBenchmarkDatasetError(f"{location}: tags must be unique")
    if any(_TAG_PATTERN.fullmatch(tag) is None for tag in tags):
        raise SinkBenchmarkDatasetError(f"{location}: tag is invalid")
    return tags
