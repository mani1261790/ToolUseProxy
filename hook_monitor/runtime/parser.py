from __future__ import annotations

import hashlib
import json
from typing import Any

from hook_monitor.runtime.ids import make_artifact_id, make_event_id
from hook_monitor.runtime.fragments import build_artifact_fragments
from hook_monitor.runtime.models import ArtifactFragment, ArtifactRecord, NormalizedEvent
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text, stringify_content


class HookPayloadError(ValueError):
    """Raised when the hook payload is not valid JSON."""


def parse_hook_payload(raw_bytes: bytes) -> dict[str, Any]:
    if not raw_bytes.strip():
        return {}
    try:
        payload = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise HookPayloadError(f"invalid hook payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise HookPayloadError("hook payload must be a JSON object")
    return payload


def normalize_event(phase: str, payload: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=make_event_id(phase, payload),
        phase=phase,
        session_id=_optional_str(payload, "session_id"),
        turn_id=_optional_str(payload, "turn_id"),
        tool_use_id=_optional_str(payload, "tool_use_id"),
        tool_name=_optional_str(payload, "tool_name"),
        cwd=_optional_str(payload, "cwd"),
        model=_optional_str(payload, "model"),
        permission_mode=_optional_str(payload, "permission_mode"),
        transcript_path=_optional_str(payload, "transcript_path"),
        raw_payload=payload,
    )


def build_artifacts(event: NormalizedEvent) -> list[ArtifactRecord]:
    raw_payload = event.raw_payload
    artifacts: list[ArtifactRecord] = []
    for role, field_name in _artifact_fields_for_phase(event.phase):
        if field_name not in raw_payload:
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
