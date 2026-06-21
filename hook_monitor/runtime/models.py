from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    phase: str
    session_id: str | None
    turn_id: str | None
    tool_use_id: str | None
    tool_name: str | None
    cwd: str | None
    model: str | None
    permission_mode: str | None
    transcript_path: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    event_id: str
    role: str
    text: str
    text_hash: str
    normalized_text: str
    token_count: int


@dataclass(frozen=True)
class ProtectedSource:
    source_id: str
    path: str
    source_type: str
    sensitivity: str
    policy_tags: tuple[str, ...]


@dataclass(frozen=True)
class SourceChunk:
    chunk_id: str
    source_id: str
    ordinal: int
    text: str
    normalized_text: str
    text_hash: str
    shingle_fingerprint: str
    token_count: int


@dataclass(frozen=True)
class FlowEdge:
    edge_id: str
    src_node_kind: str
    src_node_id: str
    dst_artifact_id: str
    method: str
    score: float
    reason: str
