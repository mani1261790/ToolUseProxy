from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DATASET_VERSION = "1.0.0"
DATASET_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
RUNNER_VERSION = "network-egress-differential-v1"

SUPPORTED_SPLITS = frozenset({"development", "validation"})
PROGRAM_FAMILIES = frozenset(
    {
        "curl",
        "git",
        "python_http",
        "node_fetch",
        "netcat",
        "custom_binary",
        "dns_client",
        "mcp_tool",
        "hosted_web_search",
    }
)
INVOCATION_SHAPES = frozenset(
    {"direct", "wrapper", "interpreter", "custom", "hosted"}
)
TRANSPORTS = frozenset({"http", "https", "tcp", "udp", "dns", "hosted"})
DESTINATION_CLASSES = frozenset(
    {"loopback", "private", "public", "reserved", "unknown", "hosted"}
)
GROUND_TRUTHS = frozenset(
    {"external_attempt", "local_attempt", "no_attempt", "hosted_external", "unobservable"}
)
ADAPTER_CLASSIFICATIONS = frozenset({"external", "local", "unknown", "unavailable"})
OBSERVER_RESULTS = frozenset(
    {"observed_attempt", "observed_no_attempt", "unobserved", "not_applicable"}
)
JOIN_STATUSES = frozenset({"exact", "ambiguous", "unjoined", "not_applicable"})
PAYLOAD_CLASSES = frozenset({"public", "protected"})
HOOK_VISIBILITIES = frozenset({"visible", "not_visible", "unknown"})
OUTCOMES = frozenset({"succeeded", "failed", "blocked", "not_run", "unknown"})

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MANIFEST_KEYS = frozenset(
    {"schema_version", "dataset_id", "dataset_version", "files"}
)
_CASE_KEYS = frozenset(
    {
        "id",
        "schema_version",
        "dataset_version",
        "split",
        "program_family",
        "invocation_shape",
        "transport",
        "destination_class",
        "ground_truth",
        "adapter_classification",
        "observer_result",
        "join_status",
        "payload_class",
        "hook_visibility",
        "outcome",
    }
)


class NetworkEgressDatasetError(ValueError):
    """Raised when a network-egress fixture violates its value-free contract."""


@dataclass(frozen=True)
class NetworkEgressCase:
    case_id: str
    split: str
    program_family: str
    invocation_shape: str
    transport: str
    destination_class: str
    ground_truth: str
    adapter_classification: str
    observer_result: str
    join_status: str
    payload_class: str
    hook_visibility: str
    outcome: str


@dataclass(frozen=True)
class NetworkEgressDataset:
    dataset_id: str
    dataset_version: str
    digest_sha256: str
    cases: tuple[NetworkEgressCase, ...]

    def select_cases(self, split: str | None = None) -> tuple[NetworkEgressCase, ...]:
        if split is not None and split not in SUPPORTED_SPLITS:
            raise NetworkEgressDatasetError(f"unsupported dataset split: {split}")
        if split is None:
            return self.cases
        return tuple(case for case in self.cases if case.split == split)


def load_network_egress_dataset(root: Path) -> NetworkEgressDataset:
    root = Path(root)
    manifest_path = root / "manifest.json"
    manifest = _load_object(manifest_path)
    _require_exact_keys(manifest, _MANIFEST_KEYS, manifest_path)
    if manifest["schema_version"] != DATASET_SCHEMA_VERSION:
        raise NetworkEgressDatasetError(
            f"{manifest_path}: schema_version must be {DATASET_SCHEMA_VERSION}"
        )
    if manifest["dataset_version"] != DATASET_VERSION:
        raise NetworkEgressDatasetError(f"{manifest_path}: unsupported dataset_version")
    dataset_id = _require_identifier(manifest["dataset_id"], "dataset_id", manifest_path)
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"cases"}:
        raise NetworkEgressDatasetError(
            f"{manifest_path}: files must contain exactly cases"
        )
    cases_path = _resolve_file(root, files["cases"], "files.cases", manifest_path)
    cases = tuple(
        _parse_case(record, location=f"{cases_path}:{line_no}")
        for line_no, record in _load_jsonl(cases_path)
    )
    if not cases:
        raise NetworkEgressDatasetError(f"{cases_path}: at least one case is required")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise NetworkEgressDatasetError(f"{cases_path}: case ids must be unique")
    _validate_coverage(cases, cases_path)

    digest = hashlib.sha256()
    digest.update(b"network-egress-dataset-v1\0")
    digest.update(manifest_path.read_bytes())
    digest.update(b"\0")
    digest.update(cases_path.read_bytes())
    return NetworkEgressDataset(
        dataset_id=dataset_id,
        dataset_version=DATASET_VERSION,
        digest_sha256=digest.hexdigest(),
        cases=cases,
    )


def evaluate_network_egress(
    dataset: NetworkEgressDataset,
    *,
    split: str | None = "development",
) -> dict[str, Any]:
    """Evaluate recorded, value-free observations without executing network calls."""
    cases = dataset.select_cases(split)
    if not cases:
        raise ValueError("network-egress selection must not be empty")

    local_cases = tuple(
        case
        for case in cases
        if case.ground_truth in {"external_attempt", "local_attempt", "no_attempt"}
    )
    hosted_cases = tuple(case for case in cases if case.ground_truth == "hosted_external")
    unknown_cases = tuple(case for case in cases if case.ground_truth == "unobservable")
    adapter_confusion = _confusion(
        local_cases,
        actual=lambda case: case.ground_truth == "external_attempt",
        predicted=lambda case: case.adapter_classification == "external",
    )
    observer_confusion = _confusion(
        local_cases,
        actual=lambda case: case.ground_truth in {"external_attempt", "local_attempt"},
        predicted=lambda case: case.observer_result == "observed_attempt",
    )
    observed_attempts = tuple(
        case for case in local_cases if case.observer_result == "observed_attempt"
    )
    exact_join_count = sum(case.join_status == "exact" for case in observed_attempts)
    visible_local_count = sum(case.hook_visibility == "visible" for case in local_cases)
    case_reports = [_case_report(case) for case in cases]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "runner_version": RUNNER_VERSION,
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "sha256": dataset.digest_sha256,
            "split": split or "all",
            "case_count": len(cases),
        },
        "configuration": {
            "network_execution": False,
            "production_policy_connected": False,
            "payload_values_stored": False,
            "observe_only": True,
        },
        "metrics": {
            "adapter_externality": _metrics(adapter_confusion),
            "observer_attempt": _metrics(observer_confusion),
            "unknown_egress_rate": _ratio(
                sum(
                    case.ground_truth == "external_attempt"
                    and case.adapter_classification != "external"
                    for case in local_cases
                ),
                sum(case.ground_truth == "external_attempt" for case in local_cases),
            ),
            "exact_join_rate": _ratio(exact_join_count, len(observed_attempts)),
            "local_hook_visibility_rate": _ratio(visible_local_count, len(local_cases)),
        },
        "coverage": {
            "local_case_count": len(local_cases),
            "hosted_case_count": len(hosted_cases),
            "unobservable_case_count": len(unknown_cases),
            "hosted_case_ids": [case.case_id for case in hosted_cases],
            "unobservable_case_ids": [case.case_id for case in unknown_cases],
            "program_families": sorted({case.program_family for case in cases}),
            "transports": sorted({case.transport for case in cases}),
            "destination_classes": sorted({case.destination_class for case in cases}),
        },
        "cases": case_reports,
    }
    report["privacy"] = {
        "raw_value_exposure_count": 0,
        "violation_paths": [],
    }
    report["summary"] = {
        "foundation_gate_passed": False,
        "accuracy_gated": False,
        "production_behavior_changed": False,
    }
    privacy_violations = _privacy_violations(report)
    report["privacy"].update(
        {
            "raw_value_exposure_count": len(privacy_violations),
            "violation_paths": privacy_violations,
        }
    )
    report["summary"]["foundation_gate_passed"] = not privacy_violations
    return report


def render_network_egress_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    adapter = report["metrics"]["adapter_externality"]
    observer = report["metrics"]["observer_attempt"]
    return "\n".join(
        (
            (
                f"network egress dataset={dataset['id']} version={dataset['version']} "
                f"split={dataset['split']} sha256={dataset['sha256'][:12]}"
            ),
            (
                f"cases={dataset['case_count']} local={report['coverage']['local_case_count']} "
                f"hosted={report['coverage']['hosted_case_count']} "
                f"unobservable={report['coverage']['unobservable_case_count']}"
            ),
            (
                "adapter externality "
                f"precision={_format_ratio(adapter['precision'])} "
                f"recall={_format_ratio(adapter['recall'])} "
                f"unknown_egress_rate={_format_ratio(report['metrics']['unknown_egress_rate'])}"
            ),
            (
                "observer attempt "
                f"precision={_format_ratio(observer['precision'])} "
                f"recall={_format_ratio(observer['recall'])} "
                f"exact_join_rate={_format_ratio(report['metrics']['exact_join_rate'])}"
            ),
            f"privacy raw_value_exposure_count={report['privacy']['raw_value_exposure_count']}",
            (
                "foundation gate="
                f"{'PASS' if report['summary']['foundation_gate_passed'] else 'FAIL'}"
            ),
        )
    )


def _parse_case(value: Any, *, location: object) -> NetworkEgressCase:
    if not isinstance(value, dict):
        raise NetworkEgressDatasetError(f"{location}: case must be an object")
    _require_exact_keys(value, _CASE_KEYS, location)
    if value["schema_version"] != DATASET_SCHEMA_VERSION:
        raise NetworkEgressDatasetError(f"{location}: schema_version mismatch")
    if value["dataset_version"] != DATASET_VERSION:
        raise NetworkEgressDatasetError(f"{location}: dataset_version mismatch")
    case = NetworkEgressCase(
        case_id=_require_identifier(value["id"], "id", location),
        split=_require_choice(value["split"], SUPPORTED_SPLITS, "split", location),
        program_family=_require_choice(
            value["program_family"], PROGRAM_FAMILIES, "program_family", location
        ),
        invocation_shape=_require_choice(
            value["invocation_shape"],
            INVOCATION_SHAPES,
            "invocation_shape",
            location,
        ),
        transport=_require_choice(value["transport"], TRANSPORTS, "transport", location),
        destination_class=_require_choice(
            value["destination_class"],
            DESTINATION_CLASSES,
            "destination_class",
            location,
        ),
        ground_truth=_require_choice(
            value["ground_truth"], GROUND_TRUTHS, "ground_truth", location
        ),
        adapter_classification=_require_choice(
            value["adapter_classification"],
            ADAPTER_CLASSIFICATIONS,
            "adapter_classification",
            location,
        ),
        observer_result=_require_choice(
            value["observer_result"], OBSERVER_RESULTS, "observer_result", location
        ),
        join_status=_require_choice(
            value["join_status"], JOIN_STATUSES, "join_status", location
        ),
        payload_class=_require_choice(
            value["payload_class"], PAYLOAD_CLASSES, "payload_class", location
        ),
        hook_visibility=_require_choice(
            value["hook_visibility"], HOOK_VISIBILITIES, "hook_visibility", location
        ),
        outcome=_require_choice(value["outcome"], OUTCOMES, "outcome", location),
    )
    _validate_case_semantics(case, location)
    return case


def _validate_case_semantics(case: NetworkEgressCase, location: object) -> None:
    hosted = case.ground_truth == "hosted_external"
    if hosted != (case.destination_class == "hosted" or case.transport == "hosted"):
        raise NetworkEgressDatasetError(
            f"{location}: hosted ground truth, transport, and destination must agree"
        )
    if hosted and (
        case.observer_result != "not_applicable" or case.join_status != "not_applicable"
    ):
        raise NetworkEgressDatasetError(
            f"{location}: hosted cases must be outside the local observer denominator"
        )
    if case.observer_result == "observed_attempt" and case.join_status == "not_applicable":
        raise NetworkEgressDatasetError(
            f"{location}: observed attempts require a join result"
        )
    if case.observer_result != "observed_attempt" and case.join_status in {"exact", "ambiguous"}:
        raise NetworkEgressDatasetError(
            f"{location}: exact or ambiguous joins require an observed attempt"
        )
    if case.ground_truth == "no_attempt" and case.observer_result == "observed_attempt":
        raise NetworkEgressDatasetError(
            f"{location}: no-attempt ground truth cannot have an observed attempt"
        )


def _validate_coverage(cases: tuple[NetworkEgressCase, ...], location: Path) -> None:
    for split in SUPPORTED_SPLITS:
        selected = tuple(case for case in cases if case.split == split)
        if not selected:
            raise NetworkEgressDatasetError(f"{location}: split {split} is empty")
        ground_truths = {case.ground_truth for case in selected}
        if "external_attempt" not in ground_truths:
            raise NetworkEgressDatasetError(
                f"{location}: split {split} needs an external attempt"
            )
        if not ground_truths.intersection({"local_attempt", "no_attempt"}):
            raise NetworkEgressDatasetError(
                f"{location}: split {split} needs a local negative control"
            )
        if {case.payload_class for case in selected} != PAYLOAD_CLASSES:
            raise NetworkEgressDatasetError(
                f"{location}: split {split} needs public and protected payload classes"
            )
        if "hosted_external" not in ground_truths:
            raise NetworkEgressDatasetError(
                f"{location}: split {split} needs a hosted external surface"
            )
        if "unobservable" not in ground_truths:
            raise NetworkEgressDatasetError(
                f"{location}: split {split} needs an unobservable surface"
            )


def _case_report(case: NetworkEgressCase) -> dict[str, str]:
    return {
        "id": case.case_id,
        "split": case.split,
        "program_family": case.program_family,
        "invocation_shape": case.invocation_shape,
        "transport": case.transport,
        "destination_class": case.destination_class,
        "ground_truth": case.ground_truth,
        "adapter_classification": case.adapter_classification,
        "observer_result": case.observer_result,
        "join_status": case.join_status,
        "payload_class": case.payload_class,
        "hook_visibility": case.hook_visibility,
        "outcome": case.outcome,
    }


def _confusion(
    cases: Iterable[NetworkEgressCase],
    *,
    actual: Any,
    predicted: Any,
) -> dict[str, int]:
    counts = {"true_positive": 0, "false_positive": 0, "false_negative": 0, "true_negative": 0}
    for case in cases:
        is_actual = bool(actual(case))
        is_predicted = bool(predicted(case))
        if is_actual and is_predicted:
            counts["true_positive"] += 1
        elif is_predicted:
            counts["false_positive"] += 1
        elif is_actual:
            counts["false_negative"] += 1
        else:
            counts["true_negative"] += 1
    return counts


def _metrics(confusion: dict[str, int]) -> dict[str, Any]:
    true_positive = confusion["true_positive"]
    false_positive = confusion["false_positive"]
    false_negative = confusion["false_negative"]
    return {
        "confusion": confusion,
        "precision": _ratio(true_positive, true_positive + false_positive),
        "recall": _ratio(true_positive, true_positive + false_negative),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _format_ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _privacy_violations(report: dict[str, Any]) -> list[str]:
    forbidden_keys = {
        "argv",
        "command",
        "credential",
        "dns_label",
        "host",
        "payload",
        "protected_value",
        "query",
        "raw_value",
        "url",
    }
    violations: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                nested_path = f"{path}.{key}"
                if key in forbidden_keys:
                    violations.append(nested_path)
                visit(nested, nested_path)
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                visit(nested, f"{path}[{index}]")

    visit(report, "$")
    return sorted(violations)


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NetworkEgressDatasetError(
            f"missing network-egress dataset file: {path}"
        ) from None
    except json.JSONDecodeError as error:
        raise NetworkEgressDatasetError(f"{path}: invalid JSON: {error.msg}") from None
    if not isinstance(value, dict):
        raise NetworkEgressDatasetError(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise NetworkEgressDatasetError(
            f"missing network-egress dataset file: {path}"
        ) from None
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise NetworkEgressDatasetError(
                f"{path}:{line_no}: invalid JSON: {error.msg}"
            ) from None
        if not isinstance(value, dict):
            raise NetworkEgressDatasetError(
                f"{path}:{line_no}: expected a JSON object"
            )
        records.append((line_no, value))
    return records


def _resolve_file(root: Path, value: Any, field: str, location: object) -> Path:
    text = _require_text(value, field, location)
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts:
        raise NetworkEgressDatasetError(
            f"{location}: {field} must be a contained relative path"
        )
    resolved = root / relative
    if not resolved.is_file():
        raise NetworkEgressDatasetError(f"{location}: {field} is not a file")
    return resolved


def _require_exact_keys(
    value: dict[str, Any], expected: frozenset[str], location: object
) -> None:
    actual = set(value)
    if actual != expected:
        raise NetworkEgressDatasetError(
            f"{location}: object keys differ; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _require_identifier(value: Any, field: str, location: object) -> str:
    text = _require_text(value, field, location)
    if _ID_PATTERN.fullmatch(text) is None:
        raise NetworkEgressDatasetError(f"{location}: {field} is invalid")
    return text


def _require_text(value: Any, field: str, location: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NetworkEgressDatasetError(f"{location}: {field} must be non-empty text")
    return value


def _require_choice(
    value: Any,
    choices: frozenset[str],
    field: str,
    location: object,
) -> str:
    text = _require_text(value, field, location)
    if text not in choices:
        raise NetworkEgressDatasetError(f"{location}: {field} is unsupported")
    return text
