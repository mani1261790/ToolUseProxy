from __future__ import annotations

import hashlib
import json
from typing import Any

from hook_monitor.runtime.models import ArtifactFragment, ArtifactRecord
from hook_monitor.runtime.normalize import estimate_token_count, normalize_text


def build_artifact_fragments(artifact: ArtifactRecord) -> list[ArtifactFragment]:
    """Artifact全体と、JSON内の意味のある末端文字列を比較単位に分ける。"""
    fragments = [_make_fragment(artifact, "/", artifact.role, artifact.text)]

    try:
        payload = json.loads(artifact.text)
    except json.JSONDecodeError:
        return fragments

    seen = {(artifact.role, artifact.normalized_text)}
    for pointer, key, value in _walk_scalar_values(payload):
        text = str(value)
        normalized = normalize_text(text)
        semantic_role = _semantic_role(artifact.role, key)
        identity = (semantic_role, normalized)
        if not normalized or identity in seen:
            continue
        seen.add(identity)
        fragments.append(_make_fragment(artifact, pointer, semantic_role, text))
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
    )


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")
