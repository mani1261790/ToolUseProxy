from __future__ import annotations

import hashlib
import json
from typing import Any


def make_event_id(
    phase: str,
    payload: dict[str, Any],
    *,
    workspace_namespace_id: str | None = None,
) -> str:
    parts = [
        phase,
        _optional_str(payload.get("session_id")),
        _optional_str(payload.get("turn_id")),
        _optional_str(payload.get("tool_use_id")),
        _optional_str(payload.get("tool_name")),
    ]
    identity_payload: Any = payload
    if workspace_namespace_id is not None:
        identity_payload = {
            "workspace_namespace_id": workspace_namespace_id,
            "payload": payload,
        }
    digest = hashlib.sha256(
        _stable_json(identity_payload).encode("utf-8")
    ).hexdigest()[:16]
    return ":".join(parts + [digest])


def make_artifact_id(event_id: str, role: str, text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{event_id}:{role}:{digest}"


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _optional_str(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)
