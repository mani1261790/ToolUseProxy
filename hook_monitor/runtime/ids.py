from __future__ import annotations

import hashlib
import json
from typing import Any


def make_event_id(phase: str, payload: dict[str, Any]) -> str:
    parts = [
        phase,
        _optional_str(payload.get("session_id")),
        _optional_str(payload.get("turn_id")),
        _optional_str(payload.get("tool_use_id")),
        _optional_str(payload.get("tool_name")),
    ]
    digest = hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()[:16]
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
