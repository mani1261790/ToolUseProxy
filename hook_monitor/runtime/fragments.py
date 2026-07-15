from __future__ import annotations

import hashlib
import json
from typing import Any

from hook_monitor.runtime.models import ArtifactFragment, ArtifactRecord
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text


def build_artifact_fragments(artifact: ArtifactRecord) -> list[ArtifactFragment]:
    """Artifact全体と、JSON内の意味のある末端文字列を比較単位に分ける。"""
    fragments = [
        _make_fragment(
            artifact,
            "/",
            artifact.role,
            artifact.text,
            fragment_kind="artifact_root",
        )
    ]

    try:
        payload = json.loads(artifact.text)
    except json.JSONDecodeError:
        return fragments

    for pointer, key, value in _walk_scalar_values(payload):
        text = str(value)
        semantic_role = _semantic_role(artifact.role, key)
        fragments.append(_make_fragment(artifact, pointer, semantic_role, text))
    if artifact.role == "tool_input":
        for pointer, key in _walk_object_keys(payload):
            fragments.append(_make_key_fragment(artifact, pointer, key))
    return fragments


def _walk_scalar_values(value: Any, pointer: str = "") -> list[tuple[str, str, Any]]:
    values: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = f"{pointer}/{_escape_pointer(str(key))}"
            if isinstance(child, (dict, list)):
                values.extend(_walk_scalar_values(child, child_pointer))
            elif isinstance(child, (str, int, float, bool)):
                values.append((child_pointer, str(key), child))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_pointer = f"{pointer}/{index}"
            if isinstance(child, (dict, list)):
                values.extend(_walk_scalar_values(child, child_pointer))
            elif isinstance(child, (str, int, float, bool)):
                values.append((child_pointer, str(index), child))
    return values


def _walk_object_keys(value: Any, pointer: str = "") -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_pointer = f"{pointer}/{_escape_pointer(key_text)}"
            keys.append((child_pointer, key_text))
            if isinstance(child, (dict, list)):
                keys.extend(_walk_object_keys(child, child_pointer))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                keys.extend(_walk_object_keys(child, f"{pointer}/{index}"))
    return keys


def _semantic_role(artifact_role: str, key: str) -> str:
    if artifact_role == "final_answer":
        return "final_answer"
    lowered = key.lower()
    role_by_key = {
        "command": "command",
        "cmd": "command",
        "query": "query",
        "search_query": "search_query",
        "path": "path",
        "file_path": "path",
        "filepath": "path",
        "content": "content",
        "contents": "content",
        "data": "content",
        "text": "content",
        "message": "content",
        "body": "content",
        "description": "content",
        "comment": "content",
        "title": "content",
        "attachment_text": "content",
        "stdout": "stdout",
        "stderr": "stderr",
        "output": "tool_output",
        "response": "tool_output",
        "server": "server",
        "server_name": "server",
        "mcp_server": "server",
        "tool": "tool",
        "tool_name": "tool",
        "mcp_tool": "tool",
    }
    return role_by_key.get(lowered, artifact_role)


def _make_fragment(
    artifact: ArtifactRecord,
    json_pointer: str,
    semantic_role: str,
    text: str,
    *,
    fragment_kind: str = "payload",
) -> ArtifactFragment:
    normalized = normalize_text(text)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    pointer_digest = hashlib.sha256(json_pointer.encode("utf-8")).hexdigest()[:10]
    return ArtifactFragment(
        fragment_id=f"{artifact.artifact_id}:fragment:{pointer_digest}:{digest[:16]}",
        artifact_id=artifact.artifact_id,
        json_pointer=json_pointer,
        semantic_role=semantic_role,
        text=text,
        text_hash=digest,
        normalized_text=normalized,
        token_count=estimate_token_count(normalized),
        fragment_kind=fragment_kind,
    )


def _make_key_fragment(
    artifact: ArtifactRecord,
    json_pointer: str,
    key: str,
) -> ArtifactFragment:
    normalized = normalize_text(key)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    pointer_digest = hashlib.sha256(json_pointer.encode("utf-8")).hexdigest()[:10]
    return ArtifactFragment(
        fragment_id=(
            f"{artifact.artifact_id}:fragment:key:{pointer_digest}:{digest[:16]}"
        ),
        artifact_id=artifact.artifact_id,
        json_pointer=json_pointer,
        semantic_role="json_key",
        text=key,
        text_hash=digest,
        normalized_text=normalized,
        token_count=estimate_token_count(normalized),
        fragment_kind="json_key",
    )


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def is_artifact_root_fragment(fragment: ArtifactFragment) -> bool:
    """Identify current roots and legacy roots stored before the kind existed."""
    if fragment.fragment_kind == "artifact_root":
        return True
    if fragment.json_pointer != "/":
        return False
    artifact_text_digest = fragment.artifact_id.rsplit(":", 1)[-1]
    return artifact_text_digest == fragment.text_hash[:16]
