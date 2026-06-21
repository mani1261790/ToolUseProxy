from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hook_monitor.runtime.models import ProtectedSource


DEFAULT_CONFIG_PATH = Path("protected_sources.json")


class SourceConfigError(ValueError):
    """Raised when the protected sources config is malformed."""


def load_protected_sources(config_path: Path) -> list[ProtectedSource]:
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []

    payload = json.loads(raw_text)
    if not isinstance(payload, dict):
        raise SourceConfigError("protected sources config must be a JSON object")

    raw_sources = payload.get("sources", [])
    if not isinstance(raw_sources, list):
        raise SourceConfigError("'sources' must be a list")

    sources: list[ProtectedSource] = []
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            raise SourceConfigError("each source entry must be an object")
        sources.append(_parse_source(raw_source))
    return sources


def _parse_source(raw_source: dict[str, Any]) -> ProtectedSource:
    source_id = _required_str(raw_source, "id")
    path = _required_str(raw_source, "path")
    source_type = _required_str(raw_source, "type")
    sensitivity = _required_str(raw_source, "sensitivity")
    raw_policy_tags = raw_source.get("policy_tags", [])
    if not isinstance(raw_policy_tags, list) or not all(
        isinstance(tag, str) for tag in raw_policy_tags
    ):
        raise SourceConfigError("'policy_tags' must be a list of strings")
    return ProtectedSource(
        source_id=source_id,
        path=path,
        source_type=source_type,
        sensitivity=sensitivity,
        policy_tags=tuple(raw_policy_tags),
    )


def _required_str(raw_source: dict[str, Any], key: str) -> str:
    value = raw_source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SourceConfigError(f"'{key}' must be a non-empty string")
    return value
