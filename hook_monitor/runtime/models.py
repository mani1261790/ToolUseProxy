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
class ArtifactFragment:
    fragment_id: str
    artifact_id: str
    json_pointer: str
    semantic_role: str
    text: str
    text_hash: str
    normalized_text: str
    token_count: int


@dataclass(frozen=True)
class ArtifactContext:
    fragment: ArtifactFragment
    artifact_role: str
    event_id: str
    phase: str
    session_id: str | None
    turn_id: str | None
    tool_use_id: str | None
    tool_name: str | None
    cwd: str | None
    sequence_no: int


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
class ResourceVersion:
    node_id: str
    path: str
    content_hash: str | None
    sequence_no: int
    session_id: str | None
    origin_tool_use_id: str | None


@dataclass(frozen=True)
class SinkCandidate:
    node_id: str
    sink_type: str
    label: str
    tool_name: str | None
    tool_use_id: str | None
    session_id: str | None
    sequence_no: int
    metadata: dict[str, object]


@dataclass(frozen=True)
class FlowEdge:
    edge_id: str
    src_node_kind: str
    src_node_id: str
    dst_node_kind: str
    dst_node_id: str
    relation: str
    evidence_level: str
    method: str
    score: float
    reason: str


@dataclass(frozen=True)
class LineageAssignment:
    analysis_run_id: str
    source_node_kind: str
    source_node_id: str
    node_kind: str
    node_id: str
    best_path_score: float
    predecessor_edge_id: str | None
    hop_count: int


@dataclass(frozen=True)
class AnalysisRun:
    analysis_run_id: str
    detector_version: str
    config_json: str
    started_at: str
    completed_at: str | None
