from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from hook_monitor.runtime.models import ProtectedSourceSelector
from hook_monitor.runtime.source_config import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    SourceConfigError,
    parse_protected_source_selector,
)


DATASET_SCHEMA_VERSION = 1
SUPPORTED_DATASET_VERSIONS = frozenset({"1.0.0", "2.0.0"})
SUPPORTED_SPLITS = frozenset({"development", "validation"})
SUPPORTED_PHASES = frozenset({"pre_tool_use", "post_tool_use", "stop"})
SUPPORTED_ACTIONS = frozenset({"allow", "warn", "block", "continue_review"})
SUPPORTED_SINK_TYPES = frozenset(
    {"external_api_call", "external_http_request", "final_answer"}
)
SUPPORTED_ADAPTERS = frozenset({"bash", "codex_final_answer", "mcp"})

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_WORKSPACE_PLACEHOLDER = "${WORKSPACE}"
_MANIFEST_KEYS = frozenset(
    {"schema_version", "dataset_id", "dataset_version", "description", "files"}
)
_SCENARIO_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "provenance",
        "source",
        "events",
        "expected_sink_type",
        "expected_adapter",
        "should_reach_sink",
        "expected_action",
        "observe_only",
        "tags",
        "rationale",
    }
)
_SOURCE_KEYS_V1 = frozenset(
    {
        "id",
        "path",
        "type",
        "sensitivity",
        "policy_tags",
        "content",
        "protected_values",
    }
)
_SOURCE_KEYS_V2 = _SOURCE_KEYS_V1 | {"selector"}
_EVENT_KEYS = frozenset({"phase", "payload"})
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


class SourceIngestionDatasetError(ValueError):
    """Raised when a source-ingestion evaluation fixture violates its contract."""


@dataclass(frozen=True)
class SourceFixture:
    source_key: str
    path: str
    source_type: str
    sensitivity: str
    policy_tags: tuple[str, ...]
    content: str
    protected_values: tuple[str, ...]
    selector: ProtectedSourceSelector | None


@dataclass(frozen=True)
class RawHookEvent:
    phase: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class SourceIngestionScenario:
    scenario_id: str
    split: str
    source: SourceFixture
    events: tuple[RawHookEvent, ...]
    expected_sink_type: str
    expected_adapter: str
    should_reach_sink: bool
    expected_action: str
    observe_only: bool
    tags: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class SourceIngestionDataset:
    dataset_id: str
    dataset_version: str
    description: str
    digest_sha256: str
    scenarios: tuple[SourceIngestionScenario, ...]

    def select_scenarios(
        self,
        split: str | None = None,
    ) -> tuple[SourceIngestionScenario, ...]:
        if split is not None and split not in SUPPORTED_SPLITS:
            raise SourceIngestionDatasetError(f"unsupported dataset split: {split}")
        if split is None:
            return self.scenarios
        return tuple(item for item in self.scenarios if item.split == split)


def load_source_ingestion_dataset(root: Path) -> SourceIngestionDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_json_object(manifest_path)
    _require_exact_keys(manifest, _MANIFEST_KEYS, manifest_path)
    dataset_version = _require_version(manifest, manifest_path)
    dataset_id = _require_identifier(
        manifest["dataset_id"],
        "dataset_id",
        manifest_path,
    )
    description = _require_nonempty_string(
        manifest["description"],
        "description",
        manifest_path,
    )
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"scenarios"}:
        raise SourceIngestionDatasetError(
            f"{manifest_path}: files must contain exactly scenarios"
        )
    scenario_path = _resolve_fixture_file(
        root,
        files["scenarios"],
        "files.scenarios",
        manifest_path,
    )
    records = _load_jsonl(scenario_path)
    scenarios = tuple(
        _parse_scenario(
            record,
            scenario_path,
            line_no,
            dataset_version=dataset_version,
        )
        for line_no, record in records
    )
    if not scenarios:
        raise SourceIngestionDatasetError(
            f"{scenario_path}: at least one scenario is required"
        )
    ids = [item.scenario_id for item in scenarios]
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    if duplicates:
        raise SourceIngestionDatasetError(
            f"dataset case ids must be unique: {', '.join(duplicates)}"
        )
    _validate_dataset_coverage(scenarios)
    return SourceIngestionDataset(
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        description=description,
        digest_sha256=_dataset_digest((manifest_path, scenario_path)),
        scenarios=scenarios,
    )


def materialize_payload(payload: dict[str, Any], workspace: Path) -> dict[str, Any]:
    """Return one fixture payload with only the declared workspace placeholder replaced."""
    materialized = json.loads(json.dumps(payload, ensure_ascii=False, allow_nan=False))
    if materialized.get("cwd") != _WORKSPACE_PLACEHOLDER:
        raise SourceIngestionDatasetError(
            "source-ingestion event cwd must use the workspace placeholder"
        )
    materialized["cwd"] = str(workspace)
    return materialized


def _parse_scenario(
    record: dict[str, Any],
    path: Path,
    line_no: int,
    *,
    dataset_version: str,
) -> SourceIngestionScenario:
    location = f"{path}:{line_no}"
    _require_exact_keys(record, _SCENARIO_KEYS, location)
    _require_version(record, location, expected_dataset_version=dataset_version)
    if record["provenance"] != "synthetic":
        raise SourceIngestionDatasetError(
            f"{location}: provenance must be synthetic"
        )
    scenario_id = _require_identifier(record["id"], "id", location)
    split = _require_choice(record["split"], "split", SUPPORTED_SPLITS, location)
    source = _parse_source(
        record["source"],
        location,
        dataset_version=dataset_version,
    )
    events = _parse_events(record["events"], location)
    expected_sink_type = _require_choice(
        record["expected_sink_type"],
        "expected_sink_type",
        SUPPORTED_SINK_TYPES,
        location,
    )
    expected_adapter = _require_choice(
        record["expected_adapter"],
        "expected_adapter",
        SUPPORTED_ADAPTERS,
        location,
    )
    expected_adapter_for_sink = {
        "external_api_call": "mcp",
        "external_http_request": "bash",
        "final_answer": "codex_final_answer",
    }[expected_sink_type]
    if expected_adapter != expected_adapter_for_sink:
        raise SourceIngestionDatasetError(
            f"{location}: expected_adapter must be {expected_adapter_for_sink} "
            f"for {expected_sink_type}"
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
        raise SourceIngestionDatasetError(
            f"{location}: an unreachable sink must have expected_action=allow"
        )
    if expected_sink_type == "final_answer" and expected_action == "block":
        raise SourceIngestionDatasetError(
            f"{location}: final_answer cannot have expected_action=block"
        )
    if expected_sink_type != "final_answer" and expected_action == "continue_review":
        raise SourceIngestionDatasetError(
            f"{location}: continue_review is reserved for final_answer"
        )
    expected_positive_action = (
        "continue_review" if expected_sink_type == "final_answer" else "block"
    )
    if should_reach and expected_action != expected_positive_action:
        raise SourceIngestionDatasetError(
            f"{location}: reachable {expected_sink_type} must expect "
            f"{expected_positive_action}"
        )
    if expected_sink_type == "final_answer" and events[-1].phase != "stop":
        raise SourceIngestionDatasetError(
            f"{location}: final_answer scenarios must end with a stop event"
        )
    if expected_sink_type != "final_answer" and events[-1].phase != "pre_tool_use":
        raise SourceIngestionDatasetError(
            f"{location}: external sink scenarios must end with a pre_tool_use event"
        )
    return SourceIngestionScenario(
        scenario_id=scenario_id,
        split=split,
        source=source,
        events=events,
        expected_sink_type=expected_sink_type,
        expected_adapter=expected_adapter,
        should_reach_sink=should_reach,
        expected_action=expected_action,
        observe_only=_require_bool(
            record["observe_only"],
            "observe_only",
            location,
        ),
        tags=_require_tags(record["tags"], location),
        rationale=_require_nonempty_string(
            record["rationale"],
            "rationale",
            location,
        ),
    )


def _parse_source(
    value: Any,
    location: object,
    *,
    dataset_version: str,
) -> SourceFixture:
    if not isinstance(value, dict):
        raise SourceIngestionDatasetError(f"{location}: source must be an object")
    source_keys = _SOURCE_KEYS_V2 if dataset_version == "2.0.0" else _SOURCE_KEYS_V1
    _require_exact_keys(value, source_keys, f"{location}.source")
    source_path = _require_relative_source_path(value["path"], location)
    source_type = _require_nonempty_string(
        value["type"],
        "source.type",
        location,
    )
    if source_type != "secretfile":
        raise SourceIngestionDatasetError(
            f"{location}: source.type must be secretfile"
        )
    content = _require_nonempty_string(
        value["content"],
        "source.content",
        location,
    )
    if len(content.encode("utf-8")) > 16 * 1024:
        raise SourceIngestionDatasetError(
            f"{location}: source.content exceeds 16384 bytes"
        )
    _validate_fixture_text(content, "source.content", location)
    raw_protected_values = value["protected_values"]
    if not isinstance(raw_protected_values, list) or not raw_protected_values:
        raise SourceIngestionDatasetError(
            f"{location}: source.protected_values must be a non-empty list"
        )
    protected_values = tuple(
        _require_nonempty_string(
            protected_value,
            "source.protected_values",
            location,
        )
        for protected_value in raw_protected_values
    )
    if len(protected_values) != len(set(protected_values)):
        raise SourceIngestionDatasetError(
            f"{location}: source.protected_values must be unique"
        )
    for protected_value in protected_values:
        _validate_fixture_text(
            protected_value,
            "source.protected_values",
            location,
        )
        if protected_value not in content:
            raise SourceIngestionDatasetError(
                f"{location}: each protected value must appear in source.content"
            )
    raw_policy_tags = value["policy_tags"]
    if not isinstance(raw_policy_tags, list) or not raw_policy_tags:
        raise SourceIngestionDatasetError(
            f"{location}: source.policy_tags must be a non-empty list"
        )
    policy_tags = tuple(
        _require_tag(tag, "source.policy_tags", location)
        for tag in raw_policy_tags
    )
    selector = None
    if dataset_version == "2.0.0":
        try:
            selector = parse_protected_source_selector(
                value["selector"],
                source_path=source_path,
                source_type=source_type,
                manifest_schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
            )
        except SourceConfigError:
            raise SourceIngestionDatasetError(
                f"{location}: source.selector is invalid"
            ) from None
        if selector is None:
            raise SourceIngestionDatasetError(
                f"{location}: source.selector is required for dataset v2"
            )
    return SourceFixture(
        source_key=_require_identifier(
            value["id"],
            "source.id",
            location,
        ),
        path=source_path,
        source_type=source_type,
        sensitivity=_require_nonempty_string(
            value["sensitivity"],
            "source.sensitivity",
            location,
        ),
        policy_tags=policy_tags,
        content=content,
        protected_values=protected_values,
        selector=selector,
    )


def _parse_events(value: Any, location: object) -> tuple[RawHookEvent, ...]:
    if not isinstance(value, list) or not 2 <= len(value) <= 6:
        raise SourceIngestionDatasetError(
            f"{location}: events must contain between 2 and 6 objects"
        )
    events: list[RawHookEvent] = []
    session_ids: set[str] = set()
    encoded_events: set[bytes] = set()
    for index, raw_event in enumerate(value):
        event_location = f"{location}.events[{index}]"
        if not isinstance(raw_event, dict):
            raise SourceIngestionDatasetError(
                f"{event_location}: event must be an object"
            )
        _require_exact_keys(raw_event, _EVENT_KEYS, event_location)
        phase = _require_choice(
            raw_event["phase"],
            "phase",
            SUPPORTED_PHASES,
            event_location,
        )
        payload = raw_event["payload"]
        if not isinstance(payload, dict):
            raise SourceIngestionDatasetError(
                f"{event_location}: payload must be an object"
            )
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise SourceIngestionDatasetError(
                f"{event_location}: payload must be finite JSON: {error}"
            ) from error
        if len(encoded) > 32 * 1024:
            raise SourceIngestionDatasetError(
                f"{event_location}: payload exceeds 32768 bytes"
            )
        if encoded in encoded_events:
            raise SourceIngestionDatasetError(
                f"{event_location}: duplicate raw events are not allowed"
            )
        encoded_events.add(encoded)
        if payload.get("cwd") != _WORKSPACE_PLACEHOLDER:
            raise SourceIngestionDatasetError(
                f"{event_location}: cwd must be {_WORKSPACE_PLACEHOLDER}"
            )
        expected_hook_name = {
            "pre_tool_use": "PreToolUse",
            "post_tool_use": "PostToolUse",
            "stop": "Stop",
        }[phase]
        if payload.get("hook_event_name") != expected_hook_name:
            raise SourceIngestionDatasetError(
                f"{event_location}: hook_event_name must be {expected_hook_name}"
            )
        session_ids.add(
            _require_nonempty_string(
                payload.get("session_id"),
                "payload.session_id",
                event_location,
            )
        )
        if phase in {"pre_tool_use", "post_tool_use"}:
            for field in ("tool_use_id", "tool_name"):
                _require_nonempty_string(
                    payload.get(field),
                    f"payload.{field}",
                    event_location,
                )
            if "tool_input" not in payload:
                raise SourceIngestionDatasetError(
                    f"{event_location}: tool_input is required"
                )
        if phase == "post_tool_use" and "tool_response" not in payload:
            raise SourceIngestionDatasetError(
                f"{event_location}: tool_response is required"
            )
        if phase == "stop" and not any(
            key in payload
            for key in (
                "last_assistant_message",
                "final_answer",
                "response",
                "assistant_response",
                "message",
            )
        ):
            raise SourceIngestionDatasetError(
                f"{event_location}: stop event requires a final answer field"
            )
        _validate_json_strings(payload, event_location)
        events.append(RawHookEvent(phase=phase, payload=payload))
    if len(session_ids) != 1:
        raise SourceIngestionDatasetError(
            f"{location}: all events must share one session_id"
        )
    return tuple(events)


def _validate_dataset_coverage(
    scenarios: tuple[SourceIngestionScenario, ...],
) -> None:
    for split in SUPPORTED_SPLITS:
        split_cases = [item for item in scenarios if item.split == split]
        if not split_cases:
            raise SourceIngestionDatasetError(
                f"dataset split {split} must contain scenarios"
            )
        if {item.should_reach_sink for item in split_cases} != {False, True}:
            raise SourceIngestionDatasetError(
                f"dataset split {split} must contain reachable and unreachable scenarios"
            )
        source_formats = {
            "dotenv" if Path(item.source.path).name.startswith(".env") else "json"
            for item in split_cases
        }
        if source_formats != {"dotenv", "json"}:
            raise SourceIngestionDatasetError(
                f"dataset split {split} must contain dotenv and JSON sources"
            )
        adapters_by_label = {
            label: {
                item.expected_adapter
                for item in split_cases
                if item.should_reach_sink == label
            }
            for label in (False, True)
        }
        if any(adapters != SUPPORTED_ADAPTERS for adapters in adapters_by_label.values()):
            raise SourceIngestionDatasetError(
                f"dataset split {split} must cover every adapter for both labels"
            )


def _validate_json_strings(value: Any, location: object) -> None:
    stack: list[tuple[str, Any, int, bool]] = [
        (str(location), value, 0, False)
    ]
    while stack:
        current_location, current, depth, workspace_placeholder_allowed = stack.pop()
        if isinstance(current, str):
            _validate_fixture_text(current, "payload string", current_location)
            if _WORKSPACE_PLACEHOLDER in current:
                if (
                    current != _WORKSPACE_PLACEHOLDER
                    or not workspace_placeholder_allowed
                ):
                    raise SourceIngestionDatasetError(
                        f"{current_location}: workspace placeholder is reserved for cwd"
                    )
        elif isinstance(current, dict):
            for index, (key, child) in enumerate(current.items()):
                key_location = f"{current_location}.key[{index}]"
                _validate_fixture_text(key, "payload key", key_location)
                if _WORKSPACE_PLACEHOLDER in key:
                    raise SourceIngestionDatasetError(
                        f"{key_location}: workspace placeholder is reserved for cwd"
                    )
                stack.append(
                    (
                        f"{current_location}.value[{index}]",
                        child,
                        depth + 1,
                        depth == 0 and key == "cwd",
                    )
                )
        elif isinstance(current, list):
            for index, child in enumerate(current):
                stack.append(
                    (f"{current_location}[{index}]", child, depth + 1, False)
                )


def _validate_fixture_text(text: str, field: str, location: object) -> None:
    for label, pattern in _FORBIDDEN_SECRET_PATTERNS:
        if pattern.search(text):
            raise SourceIngestionDatasetError(
                f"{location}: {field} resembles a real {label}"
            )


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SourceIngestionDatasetError(
            f"missing source-ingestion dataset file: {path}"
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourceIngestionDatasetError(
            f"cannot read source-ingestion dataset file {path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise SourceIngestionDatasetError(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise SourceIngestionDatasetError(
            f"missing source-ingestion dataset file: {path}"
        ) from error
    except (OSError, UnicodeError) as error:
        raise SourceIngestionDatasetError(
            f"cannot read source-ingestion dataset file {path}: {error}"
        ) from error
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            raise SourceIngestionDatasetError(
                f"{path}:{line_no}: blank JSONL lines are not allowed"
            )
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise SourceIngestionDatasetError(
                f"{path}:{line_no}: invalid JSON: {error.msg}"
            ) from error
        if not isinstance(value, dict):
            raise SourceIngestionDatasetError(
                f"{path}:{line_no}: expected a JSON object"
            )
        records.append((line_no, value))
    return records


def _resolve_fixture_file(
    root: Path,
    value: Any,
    field: str,
    location: object,
) -> Path:
    name = _require_nonempty_string(value, field, location)
    candidate = Path(name)
    if candidate.is_absolute() or len(candidate.parts) != 1 or candidate.name != name:
        raise SourceIngestionDatasetError(
            f"{location}: {field} must be a local file name"
        )
    return root / candidate


def _require_version(
    record: dict[str, Any],
    location: object,
    *,
    expected_dataset_version: str | None = None,
) -> str:
    if record.get("schema_version") != DATASET_SCHEMA_VERSION:
        raise SourceIngestionDatasetError(
            f"{location}: schema_version must be {DATASET_SCHEMA_VERSION}"
        )
    dataset_version = record.get("dataset_version")
    if dataset_version not in SUPPORTED_DATASET_VERSIONS:
        raise SourceIngestionDatasetError(
            f"{location}: dataset_version is not supported"
        )
    if (
        expected_dataset_version is not None
        and dataset_version != expected_dataset_version
    ):
        raise SourceIngestionDatasetError(
            f"{location}: dataset_version must match the manifest"
        )
    return dataset_version


def _require_exact_keys(
    value: dict[str, Any],
    expected: frozenset[str],
    location: object,
) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown or missing:
        details = []
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        if missing:
            details.append(f"missing={','.join(missing)}")
        raise SourceIngestionDatasetError(
            f"{location}: schema fields differ: {'; '.join(details)}"
        )


def _require_identifier(value: Any, field: str, location: object) -> str:
    text = _require_nonempty_string(value, field, location)
    if not _ID_PATTERN.fullmatch(text):
        raise SourceIngestionDatasetError(
            f"{location}: {field} must be a lowercase identifier"
        )
    return text


def _require_relative_source_path(value: Any, location: object) -> str:
    text = _require_nonempty_string(value, "source.path", location)
    candidate = PurePosixPath(text)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or "\\" in text
        or text in {"", "."}
    ):
        raise SourceIngestionDatasetError(
            f"{location}: source.path must be a relative workspace path"
        )
    name = candidate.name
    if not (name.startswith(".env") or name.endswith(".json")):
        raise SourceIngestionDatasetError(
            f"{location}: source.path must be dotenv or JSON"
        )
    return text


def _require_nonempty_string(value: Any, field: str, location: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceIngestionDatasetError(
            f"{location}: {field} must be a non-empty string"
        )
    return value


def _require_choice(
    value: Any,
    field: str,
    choices: frozenset[str],
    location: object,
) -> str:
    text = _require_nonempty_string(value, field, location)
    if text not in choices:
        raise SourceIngestionDatasetError(
            f"{location}: {field} must be one of {', '.join(sorted(choices))}"
        )
    return text


def _require_bool(value: Any, field: str, location: object) -> bool:
    if not isinstance(value, bool):
        raise SourceIngestionDatasetError(f"{location}: {field} must be boolean")
    return value


def _require_tags(value: Any, location: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise SourceIngestionDatasetError(
            f"{location}: tags must be a non-empty list"
        )
    tags = tuple(_require_tag(tag, "tags", location) for tag in value)
    if len(tags) != len(set(tags)):
        raise SourceIngestionDatasetError(f"{location}: tags must be unique")
    return tuple(sorted(tags))


def _require_tag(value: Any, field: str, location: object) -> str:
    text = _require_nonempty_string(value, field, location)
    if not _TAG_PATTERN.fullmatch(text):
        raise SourceIngestionDatasetError(
            f"{location}: {field} entries must be lowercase tags"
        )
    return text


def _dataset_digest(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256(b"tooluseproxy-source-ingestion-dataset-v1\0")
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
