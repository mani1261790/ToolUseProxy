from __future__ import annotations

import hashlib
import json
from typing import Any

from hook_monitor.analysis.adapters.mcp_profiles import escape_json_pointer_segment


REDACTION_REPLACEMENT_TEXT = "[REDACTED BY TOOLUSEPROXY]"
REDACTION_REPLACEMENT_PROFILE = "whole_field_fixed_v1"
REDACTION_PREVIEW_PLANNER_VERSION = "mcp-redaction-preview-v1"
REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS = 32
REDACTION_PREVIEW_MAX_DISTINCT_TARGETS = 16
REDACTION_PREVIEW_MAX_SOURCE_BYTES_PER_FINDING = 32 * 1024
REDACTION_PREVIEW_MAX_SOURCE_BYTES_TOTAL = 128 * 1024
REDACTION_PREVIEW_REJECTION_ORDER = (
    "invalid_call_scope",
    "unsupported_tool",
    "input_not_object",
    "field_count_exceeded",
    "input_bytes_exceeded",
    "nesting_depth_exceeded",
    "unsupported_input_type",
    "unknown_profile",
    "profile_unknown_field",
    "profile_missing_required_field",
    "profile_wrong_field_type",
    "profile_unsupported_nesting",
    "profile_unsupported_null",
    "file_input_unsupported",
    "post_input_unstable",
    "duplicate_sink_id",
    "sink_scope_mismatch",
    "profile_version_mismatch",
    "unsupported_target_fragment",
    "sink_field_metadata_mismatch",
    "sink_pointer_unresolved",
    "sink_coverage_incomplete",
    "critical_finding_limit_exceeded",
    "duplicate_finding_id",
    "finding_scope_mismatch",
    "critical_policy_mismatch",
    "unsupported_source_kind",
    "source_evidence_missing",
    "source_scope_mismatch",
    "source_integrity_mismatch",
    "empty_source_text",
    "source_bytes_per_finding_exceeded",
    "source_bytes_total_exceeded",
    "target_not_redactable",
    "target_not_string",
    "replacement_contains_source",
    "direct_raw_match_missing",
    "target_limit_exceeded",
    "replacement_noop",
    "unexpected_input_diff",
    "structure_changed",
    "control_changed",
    "profile_revalidation_failed",
    "planner_deadline_exceeded",
)
REDACTION_PREVIEW_REJECTION_CODES = frozenset(
    REDACTION_PREVIEW_REJECTION_ORDER
)


def canonical_json_bytes(value: object) -> bytes | None:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None


def sha256_bytes(value: bytes | None) -> str | None:
    return hashlib.sha256(value).hexdigest() if value is not None else None


def structure_sha256(value: object) -> str | None:
    try:
        entries: list[tuple[str, str]] = []
        _append_structure_entries(value, "", entries)
        encoded = json.dumps(
            entries,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def top_level_pointer_key(pointer: str) -> str:
    if not pointer.startswith("/") or pointer == "/" or pointer.count("/") != 1:
        raise ValueError("unsupported top-level JSON Pointer")
    return pointer[1:].replace("~1", "/").replace("~0", "~")


def top_level_pointer_value(
    arguments: dict[str, Any],
    pointer: str,
) -> object:
    try:
        return arguments[top_level_pointer_key(pointer)]
    except (KeyError, ValueError):
        return None


def replace_top_level_pointer(
    arguments: dict[str, Any],
    pointer: str,
    replacement: str,
) -> None:
    key = top_level_pointer_key(pointer)
    if key not in arguments:
        raise ValueError("redaction target pointer is unresolved")
    arguments[key] = replacement


def _append_structure_entries(
    value: object,
    pointer: str,
    entries: list[tuple[str, str]],
) -> None:
    if isinstance(value, dict):
        entries.append((pointer, "object"))
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError("JSON object key is not a string")
            child_pointer = f"{pointer}/{escape_json_pointer_segment(key)}"
            _append_structure_entries(value[key], child_pointer, entries)
        return
    if isinstance(value, list):
        entries.append((pointer, "array"))
        for index, child in enumerate(value):
            _append_structure_entries(child, f"{pointer}/{index}", entries)
        return
    entries.append((pointer, _json_type(value)))


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return "unsupported"
