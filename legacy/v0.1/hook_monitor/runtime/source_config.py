from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from hook_monitor.runtime.models import ProtectedSource, ProtectedSourceSelector


DEFAULT_CONFIG_PATH = Path("protected_sources.json")
CURRENT_MANIFEST_SCHEMA_VERSION = 2
LEGACY_MANIFEST_SCHEMA_VERSION = 1
MAX_SOURCE_SELECTOR_VALUES = 256
MAX_SOURCE_SELECTOR_VALUE_BYTES = 4096
_DOTENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
_INVALID_JSON_POINTER_ESCAPE = re.compile(r"~(?![01])")
_SELECTOR_KINDS = frozenset({"dotenv_keys", "json_pointers"})


class SourceConfigError(ValueError):
    """Raised when the protected sources config is malformed."""


class ProtectedSourceUnavailableError(ValueError):
    """Raised when a registered source no longer resolves to a safe file."""


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

    schema_version = payload.get(
        "schema_version",
        LEGACY_MANIFEST_SCHEMA_VERSION,
    )
    if type(schema_version) is not int or schema_version not in {
        LEGACY_MANIFEST_SCHEMA_VERSION,
        CURRENT_MANIFEST_SCHEMA_VERSION,
    }:
        raise SourceConfigError(
            "'schema_version' must be 1 or "
            f"{CURRENT_MANIFEST_SCHEMA_VERSION}"
        )

    raw_sources = payload.get("sources", [])
    if not isinstance(raw_sources, list):
        raise SourceConfigError("'sources' must be a list")

    sources: list[ProtectedSource] = []
    source_ids: set[str] = set()
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            raise SourceConfigError("each source entry must be an object")
        source = _parse_source(
            raw_source,
            workspace_id=workspace_id,
            manifest_schema_version=schema_version,
        )
        if source.source_id in source_ids:
            raise SourceConfigError("protected source ids must be unique")
        source_ids.add(source.source_id)
        sources.append(source)
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
        raise ProtectedSourceUnavailableError(
            "protected source path must be a non-symlink regular file inside workspace"
        ) from None


def _parse_source(
    raw_source: dict[str, Any],
    *,
    workspace_id: str | None,
    manifest_schema_version: int,
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
    if "selector" in raw_source and raw_source["selector"] is None:
        raise SourceConfigError("'selector' must be an object when present")
    selector = parse_protected_source_selector(
        raw_source.get("selector"),
        source_path=path,
        source_type=source_type,
        manifest_schema_version=manifest_schema_version,
    )
    return ProtectedSource(
        source_id=source_id,
        path=path,
        source_type=source_type,
        sensitivity=sensitivity,
        policy_tags=tuple(raw_policy_tags),
        workspace_id=workspace_id,
        source_key=source_key if workspace_id is not None else None,
        selector=selector,
    )


def parse_protected_source_selector(
    raw_selector: object,
    *,
    source_path: str,
    source_type: str,
    manifest_schema_version: int = CURRENT_MANIFEST_SCHEMA_VERSION,
) -> ProtectedSourceSelector | None:
    if raw_selector is None:
        return None
    if manifest_schema_version < CURRENT_MANIFEST_SCHEMA_VERSION:
        raise SourceConfigError(
            "source selectors require protected_sources.json schema_version 2"
        )
    if source_type != "secretfile":
        raise SourceConfigError("'selector' is supported only for secretfile sources")
    if not isinstance(raw_selector, dict) or len(raw_selector) != 1:
        raise SourceConfigError(
            "'selector' must contain exactly one of dotenv_keys or json_pointers"
        )
    kind = next(iter(raw_selector))
    if kind not in _SELECTOR_KINDS:
        raise SourceConfigError(
            "'selector' must contain exactly one of dotenv_keys or json_pointers"
        )
    raw_values = raw_selector[kind]
    if (
        not isinstance(raw_values, list)
        or not raw_values
        or len(raw_values) > MAX_SOURCE_SELECTOR_VALUES
        or not all(isinstance(value, str) for value in raw_values)
    ):
        raise SourceConfigError(
            f"selector.{kind} must be a non-empty list of at most "
            f"{MAX_SOURCE_SELECTOR_VALUES} strings"
        )
    values = tuple(raw_values)
    if len(set(values)) != len(values):
        raise SourceConfigError(f"selector.{kind} must not contain duplicates")
    if any(
        len(value.encode("utf-8")) > MAX_SOURCE_SELECTOR_VALUE_BYTES
        for value in values
    ):
        raise SourceConfigError(f"selector.{kind} value is too long")

    path = Path(source_path)
    name = path.name.casefold()
    is_dotenv = name == ".env" or name.startswith(".env.")
    is_json = path.suffix.casefold() == ".json"
    if kind == "dotenv_keys":
        if not is_dotenv:
            raise SourceConfigError(
                "selector.dotenv_keys requires a .env or .env.* source path"
            )
        if any(_DOTENV_KEY.fullmatch(value) is None for value in values):
            raise SourceConfigError("selector.dotenv_keys contains an invalid key")
    else:
        if not is_json or is_dotenv:
            raise SourceConfigError(
                "selector.json_pointers requires a .json source path"
            )
        if any(not _valid_json_pointer(value) for value in values):
            raise SourceConfigError(
                "selector.json_pointers contains an invalid RFC 6901 pointer"
            )
    return ProtectedSourceSelector(kind=kind, values=tuple(sorted(values)))


def protected_source_selector_payload(
    selector: ProtectedSourceSelector | None,
) -> dict[str, list[str]] | None:
    if selector is None:
        return None
    return {selector.kind: list(selector.values)}


def _valid_json_pointer(value: str) -> bool:
    if value and not value.startswith("/"):
        return False
    return _INVALID_JSON_POINTER_ESCAPE.search(value) is None


def _required_str(raw_source: dict[str, Any], key: str) -> str:
    value = raw_source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SourceConfigError(f"'{key}' must be a non-empty string")
    return value
