from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from hook_monitor.runtime.models import ProtectedSource


DEFAULT_CONFIG_PATH = Path("protected_sources.json")


class SourceConfigError(ValueError):
    """Raised when the protected sources config is malformed."""


SCOPED_SOURCE_ID_VERSION = "protected_source_v1"


def load_protected_sources(
    config_path: Path,
    *,
    workspace_id: str | None = None,
) -> list[ProtectedSource]:
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
        sources.append(_parse_source(raw_source, workspace_id=workspace_id))
    return sources


def make_scoped_source_id(workspace_id: str, source_key: str) -> str:
    identity = "\0".join(
        (SCOPED_SOURCE_ID_VERSION, workspace_id, source_key)
    )
    return (
        f"{SCOPED_SOURCE_ID_VERSION}_"
        f"{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"
    )


def resolve_protected_source_path(
    workspace_root: str | Path,
    source_path: str,
) -> Path:
    try:
        root = Path(workspace_root).resolve(strict=True)
        candidate = Path(source_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        lexical = os.path.abspath(os.path.normpath(str(candidate)))
        if os.path.commonpath((str(root), lexical)) != str(root):
            raise ValueError
        relative = os.path.relpath(lexical, str(root))
        parts = tuple(part for part in Path(relative).parts if part not in {"", "."})
        if not parts or any(part == ".." for part in parts):
            raise ValueError
        current = root
        for part in parts:
            current = current / part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError
        resolved = Path(os.path.realpath(lexical))
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            raise ValueError
        if not stat.S_ISREG(os.lstat(resolved).st_mode):
            raise ValueError
        return resolved
    except (OSError, RuntimeError, ValueError):
        raise ValueError(
            "protected source path must be a non-symlink regular file inside workspace"
        ) from None


def _parse_source(
    raw_source: dict[str, Any],
    *,
    workspace_id: str | None,
) -> ProtectedSource:
    source_key = _required_str(raw_source, "id")
    source_id = (
        source_key
        if workspace_id is None
        else make_scoped_source_id(workspace_id, source_key)
    )
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
        workspace_id=workspace_id,
        source_key=source_key if workspace_id is not None else None,
    )


def _required_str(raw_source: dict[str, Any], key: str) -> str:
    value = raw_source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SourceConfigError(f"'{key}' must be a non-empty string")
    return value
