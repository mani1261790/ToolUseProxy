from __future__ import annotations

import hashlib
import json
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
