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
    stop_hook_active: bool | None
    workspace_id: str | None
    workspace_root: str | None
    workspace_lexical_root: str | None
    workspace_execution_cwd: str | None
    workspace_status: str
    workspace_source: str
    workspace_namespace_id: str | None
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
    fragment_kind: str = "payload"
    parent_fragment_id: str | None = None
    operation_id: str | None = None


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
    workspace_id: str | None = None
    workspace_root: str | None = None
    workspace_lexical_root: str | None = None
    workspace_execution_cwd: str | None = None
    workspace_status: str = "legacy_unscoped"


@dataclass(frozen=True)
class ToolOperation:
    operation_id: str
    event_id: str
    artifact_id: str
    parent_fragment_id: str
    session_id: str | None
    tool_use_id: str | None
    tool_name: str | None
    adapter: str
    operation_index: int
    operation_kind: str
    source_path: str | None
    target_path: str | None
    segment_index: int | None
    connector: str | None
    content_fragment_id: str | None
    outcome: str = "unknown"
    outcome_evidence: str | None = None
    outcome_event_id: str | None = None


@dataclass(frozen=True)
class ResourceSnapshot:
    snapshot_id: str
    post_event_id: str
    operation_id: str
    session_id: str | None
    tool_use_id: str | None
    path_role: str
    requested_path: str
    workspace_root: str | None
    lexical_path: str | None
    resource_state: str
    capture_status: str
    file_kind: str
    byte_size: int | None
    captured_bytes: int
    content_sha256: str | None
    encoding: str | None
    body_text: str | None
    error_code: str | None
    duration_ms: float


@dataclass(frozen=True)
class ProtectedSource:
    source_id: str
    path: str
    source_type: str
    sensitivity: str
    policy_tags: tuple[str, ...]
    workspace_id: str | None = None
    source_key: str | None = None


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
    workspace_id: str | None = None


@dataclass(frozen=True)
class ResourceVersion:
    node_id: str
    path: str
    content_hash: str | None
    sequence_no: int
    session_id: str | None
    origin_tool_use_id: str | None
    operation_id: str | None = None
    operation_index: int | None = None
    snapshot_id: str | None = None
    resource_state: str = "present"
    workspace_id: str | None = None


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
    workspace_id: str | None = None


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


@dataclass(frozen=True)
class AnalysisCursor:
    session_id: str
    detector_version: str
    source_digest: str
    last_sequence_no: int
    status: str


@dataclass(frozen=True)
class StoredPolicyDecision:
    decision_id: str
    finding_id: str
    analysis_run_id: str
    hook_event: str | None
    action: str
    severity: str
    sink_type: str
    source_node_kind: str
    source_node_id: str
    sink_node_id: str
    path_score: float
    reason: str
    user_message: str
    technical_summary: str
    trace_command: str
    path_summary: tuple[str, ...]
    created_at: str | None = None
