from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from hook_monitor.runtime.ids import make_artifact_id, make_event_id
from hook_monitor.runtime.fragments import build_artifact_fragments
from hook_monitor.runtime.models import ArtifactFragment, ArtifactRecord, NormalizedEvent
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text, stringify_content
from hook_monitor.runtime.workspace import (
    make_configured_workspace_namespace,
    resolve_workspace,
)


class HookPayloadError(ValueError):
    """Raised when the hook payload is not valid JSON."""


class HookPayloadLimitError(HookPayloadError):
    """Raised before materialization when a bounded payload limit is exceeded."""

    def __init__(self, rejection_code: str) -> None:
        super().__init__(f"hook payload rejected: {rejection_code}")
        self.rejection_code = rejection_code


def extract_top_level_json_strings(
    raw_bytes: bytes,
    keys: frozenset[str],
    *,
    max_value_bytes: int = 4096,
) -> dict[str, str]:
    """Extract bounded top-level string members without decoding the JSON object.

    The scanner is intentionally not a general JSON parser. It is used only to
    scope the pre-decoder MCP safety gate by the small Hook envelope members that
    Codex emits before ``tool_input``. Nested lookalike keys are ignored and the
    last complete string occurrence wins, matching normal JSON object decoding.
    """
    if max_value_bytes < 1:
        raise ValueError("top-level JSON string limit must be positive")
    if not keys:
        return {}

    values: dict[str, str] = {}
    depth = 0
    index = 0
    length = len(raw_bytes)
    while index < length:
        byte = raw_bytes[index]
        if byte == ord('"'):
            string_end = _find_json_string_end(raw_bytes, index)
            if string_end is None:
                break
            if depth == 1:
                separator = _skip_json_whitespace(raw_bytes, string_end + 1)
                if separator < length and raw_bytes[separator] == ord(":"):
                    member_name = _decode_json_string(
                        raw_bytes[index : string_end + 1],
                        max_value_bytes=max_value_bytes,
                    )
                    if member_name in keys:
                        value_start = _skip_json_whitespace(
                            raw_bytes,
                            separator + 1,
                        )
                        # A later non-string duplicate must not leave an earlier
                        # string value active when the full decoder would replace it.
                        values.pop(member_name, None)
                        if (
                            value_start < length
                            and raw_bytes[value_start] == ord('"')
                        ):
                            value_end = _find_json_string_end(raw_bytes, value_start)
                            if value_end is not None:
                                value = _decode_json_string(
                                    raw_bytes[value_start : value_end + 1],
                                    max_value_bytes=max_value_bytes,
                                )
                                if value is not None:
                                    values[member_name] = value
            index = string_end + 1
            continue
        if byte in {ord("{"), ord("[")}:
            depth += 1
        elif byte in {ord("}"), ord("]")}:
            depth = max(0, depth - 1)
        index += 1
    return values


def json_nesting_exceeds_limit(raw_bytes: bytes, max_depth: int) -> bool:
    """Bound JSON container nesting without parsing or inspecting string content."""
    if max_depth < 1:
        raise ValueError("JSON nesting limit must be positive")
    depth = 0
    in_string = False
    escaped = False
    for byte in raw_bytes:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in {ord("{"), ord("[")}:
            depth += 1
            if depth > max_depth:
                return True
        elif byte in {ord("}"), ord("]")}:
            depth = max(0, depth - 1)
    return False


def parse_hook_payload(
    raw_bytes: bytes,
    *,
    max_number_chars: int | None = None,
) -> dict[str, Any]:
    if not raw_bytes.strip():
        return {}
    if max_number_chars is not None and max_number_chars < 1:
        raise ValueError("JSON numeric token limit must be positive")
    if raw_bytes.startswith(
        (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")
    ) or b"\x00" in raw_bytes:
        raise HookPayloadError("hook payload must be UTF-8 JSON without a BOM")
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HookPayloadError("hook payload must be UTF-8 JSON") from exc

    decoder_options: dict[str, Any] = {}
    if max_number_chars is not None:
        decoder_options = {
            "parse_int": lambda token: _parse_bounded_int(token, max_number_chars),
            "parse_float": lambda token: _parse_bounded_float(
                token,
                max_number_chars,
            ),
            "parse_constant": _reject_json_numeric_constant,
        }
    try:
        payload = json.loads(raw_text, **decoder_options)
    except HookPayloadLimitError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise HookPayloadError(f"invalid hook payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise HookPayloadError("hook payload must be a JSON object")
    if _contains_unencodable_unicode(payload):
        if max_number_chars is not None:
            raise HookPayloadLimitError("invalid_unicode_scalar")
        raise HookPayloadError("hook payload contains invalid Unicode scalar values")
    return payload


def _find_json_string_end(raw_bytes: bytes, start: int) -> int | None:
    escaped = False
    for index in range(start + 1, len(raw_bytes)):
        byte = raw_bytes[index]
        if escaped:
            escaped = False
        elif byte == ord("\\"):
            escaped = True
        elif byte == ord('"'):
            return index
    return None


def _skip_json_whitespace(raw_bytes: bytes, start: int) -> int:
    index = start
    while index < len(raw_bytes) and raw_bytes[index] in b" \t\r\n":
        index += 1
    return index


def _decode_json_string(
    encoded: bytes,
    *,
    max_value_bytes: int,
) -> str | None:
    if len(encoded) > max_value_bytes + 2:
        return None
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, str) else None


def _parse_bounded_int(token: str, max_number_chars: int) -> int:
    if len(token) > max_number_chars:
        raise HookPayloadLimitError("numeric_token_exceeded")
    return int(token)


def _parse_bounded_float(token: str, max_number_chars: int) -> float:
    if len(token) > max_number_chars:
        raise HookPayloadLimitError("numeric_token_exceeded")
    value = float(token)
    if not math.isfinite(value):
        raise HookPayloadLimitError("numeric_value_non_finite")
    return value


def _reject_json_numeric_constant(_token: str) -> float:
    raise HookPayloadLimitError("unsupported_numeric_constant")


def _contains_unencodable_unicode(payload: object) -> bool:
    stack = [payload]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(value, dict):
            for key, child in value.items():
                stack.append(key)
                stack.append(child)
        elif isinstance(value, list):
            stack.extend(value)
    return False


def normalize_event(
    phase: str,
    payload: dict[str, Any],
    *,
    workspace_root: str | None = None,
) -> NormalizedEvent:
    cwd = _optional_str(payload, "cwd")
    workspace = resolve_workspace(cwd, workspace_root)
    workspace_namespace_id: str | None = None
    if workspace.discovered_by == "configured_root":
        assert workspace_root is not None
        workspace_namespace_id = (
            workspace.workspace_id
            if workspace.ready
            else make_configured_workspace_namespace(workspace_root)
        )
    return NormalizedEvent(
        event_id=make_event_id(
            phase,
            payload,
            workspace_namespace_id=workspace_namespace_id,
        ),
        phase=phase,
        session_id=_optional_str(payload, "session_id"),
        turn_id=_optional_str(payload, "turn_id"),
        tool_use_id=_optional_str(payload, "tool_use_id"),
        tool_name=_optional_str(payload, "tool_name"),
        cwd=cwd,
        model=_optional_str(payload, "model"),
        permission_mode=_optional_str(payload, "permission_mode"),
        transcript_path=_optional_str(payload, "transcript_path"),
        stop_hook_active=_optional_bool(payload, "stop_hook_active"),
        workspace_id=workspace.workspace_id,
        workspace_root=workspace.canonical_root,
        workspace_lexical_root=workspace.lexical_root,
        workspace_execution_cwd=workspace.execution_cwd,
        workspace_status=workspace.status,
        workspace_source=workspace.discovered_by,
        workspace_namespace_id=workspace_namespace_id,
        raw_payload=payload,
    )


def build_artifacts(event: NormalizedEvent) -> list[ArtifactRecord]:
    raw_payload = event.raw_payload
    artifacts: list[ArtifactRecord] = []
    for role, field_name in _artifact_fields_for_phase(event.phase):
        if field_name not in raw_payload or raw_payload[field_name] is None:
            continue
        text = stringify_content(raw_payload.get(field_name))
        normalized = normalize_text(text)
        artifacts.append(
            ArtifactRecord(
                artifact_id=make_artifact_id(event.event_id, role, text),
                event_id=event.event_id,
                role=role,
                text=text,
                text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                normalized_text=normalized,
                token_count=estimate_token_count(normalized),
            )
        )
    return artifacts


def build_fragments(artifacts: list[ArtifactRecord]) -> list[ArtifactFragment]:
    return [
        fragment
        for artifact in artifacts
        for fragment in build_artifact_fragments(artifact)
    ]


def _artifact_fields_for_phase(phase: str) -> list[tuple[str, str]]:
    if phase == "pre_tool_use":
        return [("tool_input", "tool_input")]
    if phase == "post_tool_use":
        return [("tool_input", "tool_input"), ("tool_output", "tool_response")]
    if phase == "stop":
        return [
            ("final_answer", "last_assistant_message"),
            ("final_answer", "final_answer"),
            ("final_answer", "response"),
            ("final_answer", "assistant_response"),
            ("final_answer", "message"),
        ]
    return []


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    return str(value)


def _optional_bool(payload: dict[str, Any], key: str) -> bool | None:
    value = payload.get(key)
    return value if isinstance(value, bool) else None
