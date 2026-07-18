from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hook_monitor.analysis.adapters.mcp_profiles import (
    DEFAULT_MCP_INPUT_LIMITS,
    DEFAULT_MCP_PROFILE_REGISTRY,
    MCP_TOOL_NAME_MAX_BYTES,
    McpProfileRegistry,
)
from hook_monitor.analysis.adapters.mcp import parse_mcp_tool_name
from hook_monitor.analysis.leak_detection import detect_leaks
from hook_monitor.policy.redaction_decision import (
    REDACTION_DECISION_DERIVATION_VERSION,
    derive_redact_decision,
)

from hook_monitor.runtime.ids import make_event_id, make_source_chunk_id
from hook_monitor.runtime.redaction_integrity import (
    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS,
    REDACTION_PREVIEW_MAX_SOURCE_BYTES_PER_FINDING,
    REDACTION_PREVIEW_MAX_SOURCE_BYTES_TOTAL,
    REDACTION_PREVIEW_PLANNER_VERSION,
    REDACTION_PREVIEW_REJECTION_CODES,
    REDACTION_REPLACEMENT_PROFILE,
)
from hook_monitor.runtime.redaction_confirmation import (
    PostRedactionInputObservation,
    REDACTION_POST_INPUT_DIAGNOSTIC_CODES,
    REDACTION_POST_INPUT_OBSERVER_VERSION,
    RedactionPostConfirmationResult,
    compare_mcp_post_observation,
    observe_mcp_post_input,
)

from hook_monitor.runtime.models import (
    AnalysisCursor,
    AnalysisRun,
    ArtifactContext,
    ArtifactFragment,
    ArtifactRecord,
    FlowEdge,
    LineageAssignment,
    NormalizedEvent,
    ProtectedSource,
    RedactionAuditCleanupResult,
    ResourceVersion,
    ResourceSnapshot,
    RuntimeAnalysisScope,
    SinkCandidate,
    SourceChunk,
    SourceChunkEvidence,
    StoredPolicyDecision,
    StoredRedactionDecisionLink,
    StoredRedactionPlan,
    StoredRedactionTarget,
    ToolOperation,
)
from hook_monitor.runtime.workspace import (
    WORKSPACE_CONFIGURED_NAMESPACE_VERSION,
    WorkspaceContext,
    make_workspace_id,
    resolve_workspace,
)
from hook_monitor.runtime.source_config import (
    make_scoped_source_id,
    parse_protected_source_selector,
    protected_source_selector_payload,
    resolve_protected_source_path,
)

if TYPE_CHECKING:
    from hook_monitor.policy.redaction_preview import RedactionPreviewPlan


DEFAULT_DB_PATH = Path(".tooluseproxy/events.db")
CURRENT_SCHEMA_VERSION = 2
RUNTIME_REQUIRED_TABLES = frozenset(
    {
        "analysis_cursors",
        "analysis_node_snapshots",
        "analysis_run_flow_edges",
        "analysis_run_graphs",
        "analysis_run_nodes",
        "analysis_runs",
        "analysis_state",
        "artifact_fragments",
        "artifacts",
        "event_payload_metadata",
        "events",
        "flow_edges",
        "fragment_exact_index",
        "fragment_shingles",
        "information_flow_edge_scopes",
        "information_flow_edges",
        "lineage_assignments",
        "policy_decisions",
        "protected_sources",
        "redaction_decision_links",
        "redaction_plans",
        "redaction_targets",
        "resource_snapshots",
        "resource_versions",
        "runtime_lineage_state",
        "runtime_source_binding_edges",
        "sink_candidates",
        "source_binding_edges",
        "source_chunks",
        "tool_operation_outcomes",
        "tool_operations",
        "workspace_analysis_state",
        "workspaces",
    }
)
RUNTIME_REQUIRED_COLUMNS = {
    "workspaces": frozenset(
        {"workspace_id", "canonical_root", "lexical_root", "discovered_by"}
    ),
    "events": frozenset(
        {
            "event_id",
            "phase",
            "session_id",
            "turn_id",
            "tool_use_id",
            "tool_name",
            "cwd",
            "payload_json",
            "sequence_no",
            "workspace_id",
            "workspace_root",
            "workspace_lexical_root",
            "workspace_execution_cwd",
            "workspace_status",
            "workspace_source",
            "workspace_namespace_id",
        }
    ),
    "protected_sources": frozenset(
        {
            "source_id",
            "path",
            "source_type",
            "sensitivity",
            "policy_tags_json",
            "workspace_id",
            "source_key",
            "selector_json",
        }
    ),
}
LEGACY_DERIVED_WORKSPACE_ID = "legacy_unscoped"
WORKSPACE_ANALYSIS_INPUT_REVISION_VERSION = "workspace-analysis-input-v2"
REDACTION_AUDIT_BUSY_TIMEOUT_MS = 10
REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES = 1024 * 1024
REDACTION_AUDIT_MAX_CURRENT_SINKS = 2 * DEFAULT_MCP_INPUT_LIMITS.max_fields
REDACTION_AUDIT_MAX_IDENTIFIER_BYTES = MCP_TOOL_NAME_MAX_BYTES
REDACTION_AUDIT_MAX_SINK_METADATA_BYTES = 64 * 1024
REDACTION_AUDIT_MAX_SINK_BYTES_TOTAL = 512 * 1024
_EVENT_PAYLOAD_METADATA_VERSION = "event-payload-metadata-v1"
_LOWER_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_EVENT_PAYLOAD_METADATA_COLUMNS = """
    event_id,
    metadata_version,
    metadata_sha256,
    payload_bytes,
    payload_sha256,
    sequence_no,
    redaction_event_kind,
    redaction_scope_sha256,
    post_input_status,
    post_input_observer_version,
    post_input_diagnostic_code,
    post_profile_id,
    post_profile_version,
    post_profile_registry_version,
    post_input_bytes,
    post_input_sha256,
    post_structure_sha256
"""


class SchemaCompatibilityError(RuntimeError):
    """Raised when a Hook runtime cannot safely use the current database."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


_QUALIFIED_PRE_EVENT_PAYLOAD_METADATA_COLUMNS = """
    pre_scope.event_id,
    pre_scope.metadata_version,
    pre_scope.metadata_sha256,
    pre_scope.payload_bytes,
    pre_scope.payload_sha256,
    pre_scope.sequence_no,
    pre_scope.redaction_event_kind,
    pre_scope.redaction_scope_sha256,
    pre_scope.post_input_status,
    pre_scope.post_input_observer_version,
    pre_scope.post_input_diagnostic_code,
    pre_scope.post_profile_id,
    pre_scope.post_profile_version,
    pre_scope.post_profile_registry_version,
    pre_scope.post_input_bytes,
    pre_scope.post_input_sha256,
    pre_scope.post_structure_sha256
"""
REDACTION_CONFIRMATION_MAX_PLAN_CANDIDATES = 32
_REDACTION_PLAN_VALUE_COLUMNS = """
    plan_id,
    analysis_run_id,
    pre_event_id,
    workspace_id,
    session_id,
    tool_use_id,
    tool_name,
    adapter,
    profile_id,
    profile_version,
    profile_registry_version,
    mode,
    status,
    planner_version,
    original_input_sha256,
    rewritten_input_sha256,
    structure_sha256_before,
    structure_sha256_after,
    critical_finding_count,
    replacement_count,
    rejection_code,
    post_event_id,
    rendered_at,
    confirmed_at
"""
_REDACTION_PLAN_SELECT_COLUMNS = """
    plan_id,
    analysis_run_id,
    pre_event_id,
    workspace_id,
    session_id,
    tool_use_id,
    tool_name,
    adapter,
    profile_id,
    profile_version,
    profile_registry_version,
    mode,
    status,
    planner_version,
    original_input_sha256,
    rewritten_input_sha256,
    structure_sha256_before,
    structure_sha256_after,
    critical_finding_count,
    replacement_count,
    rejection_code,
    post_event_id,
    created_at,
    rendered_at,
    confirmed_at
"""
_REDACTION_TARGET_VALUE_COLUMNS = """
    plan_id,
    ordinal,
    finding_id,
    decision_id,
    source_node_kind,
    source_node_id,
    sink_node_id,
    json_pointer,
    original_value_sha256,
    replacement_profile
"""
_REDACTION_DECISION_LINK_VALUE_COLUMNS = """
    enforce_plan_id,
    target_ordinal,
    preview_plan_id,
    finding_id,
    source_block_decision_id,
    derived_redact_decision_id,
    derivation_version,
    metadata_sha256
"""
_REDACTION_DECISION_LINK_SELECT_COLUMNS = """
    enforce_plan_id,
    target_ordinal,
    preview_plan_id,
    finding_id,
    source_block_decision_id,
    derived_redact_decision_id,
    derivation_version,
    metadata_sha256,
    created_at
"""


def make_analysis_run_id() -> str:
    """Create an analysis run identity without publishing a database row."""
    return uuid.uuid4().hex


@dataclass(frozen=True)
class _EventPayloadMetadata:
    event_id: str
    payload_bytes: int
    payload_sha256: str
    sequence_no: int
    redaction_event_kind: str
    redaction_scope_sha256: str | None
    post_input_observation: PostRedactionInputObservation


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._redaction_audit_available: bool | None = None

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            _enable_wal(conn)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS workspaces (
                    workspace_id TEXT PRIMARY KEY,
                    canonical_root TEXT NOT NULL UNIQUE,
                    lexical_root TEXT NOT NULL,
                    discovered_by TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    phase TEXT NOT NULL,
                    session_id TEXT,
                    turn_id TEXT,
                    tool_use_id TEXT,
                    tool_name TEXT,
                    cwd TEXT,
                    model TEXT,
                    permission_mode TEXT,
                    transcript_path TEXT,
                    payload_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._ensure_column(conn, "events", "sequence_no", "INTEGER")
            self._ensure_column(conn, "events", "stop_hook_active", "INTEGER")
            self._ensure_column(conn, "events", "workspace_id", "TEXT")
            self._ensure_column(conn, "events", "workspace_root", "TEXT")
            self._ensure_column(conn, "events", "workspace_lexical_root", "TEXT")
            self._ensure_column(
                conn,
                "events",
                "workspace_execution_cwd",
                "TEXT",
            )
            self._ensure_column(
                conn,
                "events",
                "workspace_status",
                "TEXT NOT NULL DEFAULT 'legacy_unscoped'",
            )
            self._ensure_column(conn, "events", "workspace_source", "TEXT")
            self._ensure_column(
                conn,
                "events",
                "workspace_namespace_id",
                "TEXT",
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES events (event_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifact_fragments (
                    fragment_id TEXT PRIMARY KEY,
                    artifact_id TEXT NOT NULL,
                    json_pointer TEXT NOT NULL,
                    semantic_role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (artifact_id) REFERENCES artifacts (artifact_id)
                )
                """
            )
            self._ensure_column(
                conn,
                "artifact_fragments",
                "fragment_kind",
                "TEXT NOT NULL DEFAULT 'payload'",
            )
            self._ensure_column(
                conn,
                "artifact_fragments",
                "parent_fragment_id",
                "TEXT",
            )
            self._ensure_column(
                conn,
                "artifact_fragments",
                "operation_id",
                "TEXT",
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_operations (
                    operation_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    parent_fragment_id TEXT NOT NULL,
                    session_id TEXT,
                    tool_use_id TEXT,
                    tool_name TEXT,
                    adapter TEXT NOT NULL,
                    operation_index INTEGER NOT NULL,
                    operation_kind TEXT NOT NULL,
                    source_path TEXT,
                    target_path TEXT,
                    segment_index INTEGER,
                    connector TEXT,
                    content_fragment_id TEXT,
                    outcome TEXT NOT NULL DEFAULT 'unknown',
                    outcome_evidence TEXT,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES events (event_id),
                    FOREIGN KEY (artifact_id) REFERENCES artifacts (artifact_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_operation_outcomes (
                    post_event_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    session_id TEXT,
                    tool_use_id TEXT,
                    outcome TEXT NOT NULL,
                    outcome_evidence TEXT,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (post_event_id, operation_id),
                    FOREIGN KEY (post_event_id) REFERENCES events (event_id),
                    FOREIGN KEY (operation_id) REFERENCES tool_operations (operation_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS protected_sources (
                    source_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    sensitivity TEXT NOT NULL,
                    policy_tags_json TEXT NOT NULL,
                    selector_json TEXT NOT NULL DEFAULT 'null',
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._ensure_column(conn, "protected_sources", "workspace_id", "TEXT")
            self._ensure_column(conn, "protected_sources", "source_key", "TEXT")
            self._ensure_column(
                conn,
                "protected_sources",
                "selector_json",
                "TEXT NOT NULL DEFAULT 'null'",
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resource_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    post_event_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    session_id TEXT,
                    tool_use_id TEXT,
                    path_role TEXT NOT NULL,
                    requested_path TEXT NOT NULL,
                    workspace_root TEXT,
                    lexical_path TEXT,
                    resource_state TEXT NOT NULL,
                    capture_status TEXT NOT NULL,
                    file_kind TEXT NOT NULL,
                    byte_size INTEGER,
                    captured_bytes INTEGER NOT NULL,
                    content_sha256 TEXT,
                    encoding TEXT,
                    body_text TEXT,
                    error_code TEXT,
                    duration_ms REAL NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (post_event_id, operation_id, path_role),
                    FOREIGN KEY (post_event_id) REFERENCES events (event_id),
                    FOREIGN KEY (operation_id) REFERENCES tool_operations (operation_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS source_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    shingle_fingerprint TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_id) REFERENCES protected_sources (source_id)
                )
                """
            )
            self._ensure_column(conn, "source_chunks", "workspace_id", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS flow_edges (
                    edge_id TEXT PRIMARY KEY,
                    src_node_kind TEXT NOT NULL,
                    src_node_id TEXT NOT NULL,
                    dst_artifact_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (dst_artifact_id) REFERENCES artifacts (artifact_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    analysis_run_id TEXT PRIMARY KEY,
                    detector_version TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    completed_at TEXT
                )
                """
            )
            self._ensure_column(conn, "analysis_runs", "workspace_id", "TEXT")
            self._ensure_column(conn, "analysis_runs", "session_id", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS information_flow_edges (
                    edge_id TEXT PRIMARY KEY,
                    src_node_kind TEXT NOT NULL,
                    src_node_id TEXT NOT NULL,
                    dst_node_kind TEXT NOT NULL,
                    dst_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    evidence_level TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS source_binding_edges (
                    analysis_run_id TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    src_node_kind TEXT NOT NULL,
                    src_node_id TEXT NOT NULL,
                    dst_node_kind TEXT NOT NULL,
                    dst_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    evidence_level TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (analysis_run_id, edge_id),
                    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (analysis_run_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_run_graphs (
                    analysis_run_id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    coverage TEXT NOT NULL DEFAULT 'full',
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_run_id)
                        REFERENCES analysis_runs (analysis_run_id),
                    FOREIGN KEY (workspace_id) REFERENCES workspaces (workspace_id)
                )
                """
            )
            self._ensure_column(
                conn,
                "analysis_run_graphs",
                "coverage",
                "TEXT NOT NULL DEFAULT 'full'",
            )
            self._ensure_column(
                conn,
                "analysis_run_graphs",
                "node_snapshot_version",
                "TEXT",
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_run_flow_edges (
                    analysis_run_id TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    src_node_kind TEXT NOT NULL,
                    src_node_id TEXT NOT NULL,
                    dst_node_kind TEXT NOT NULL,
                    dst_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    evidence_level TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (analysis_run_id, edge_id),
                    FOREIGN KEY (analysis_run_id)
                        REFERENCES analysis_run_graphs (analysis_run_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_node_snapshots (
                    workspace_id TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (workspace_id, snapshot_hash),
                    FOREIGN KEY (workspace_id) REFERENCES workspaces (workspace_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_run_nodes (
                    analysis_run_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL,
                    PRIMARY KEY (analysis_run_id, node_kind, node_id),
                    FOREIGN KEY (analysis_run_id)
                        REFERENCES analysis_run_graphs (analysis_run_id),
                    FOREIGN KEY (workspace_id, snapshot_hash)
                        REFERENCES analysis_node_snapshots (
                            workspace_id,
                            snapshot_hash
                        )
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resource_versions (
                    node_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    content_hash TEXT,
                    sequence_no INTEGER NOT NULL,
                    session_id TEXT,
                    origin_tool_use_id TEXT,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._ensure_column(conn, "resource_versions", "operation_id", "TEXT")
            self._ensure_column(
                conn,
                "resource_versions",
                "operation_index",
                "INTEGER",
            )
            self._ensure_column(conn, "resource_versions", "snapshot_id", "TEXT")
            self._ensure_column(
                conn,
                "resource_versions",
                "resource_state",
                "TEXT NOT NULL DEFAULT 'present'",
            )
            self._ensure_column(conn, "resource_versions", "workspace_id", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sink_candidates (
                    node_id TEXT PRIMARY KEY,
                    sink_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    tool_name TEXT,
                    tool_use_id TEXT,
                    session_id TEXT,
                    sequence_no INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._ensure_column(conn, "sink_candidates", "workspace_id", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_cursors (
                    session_id TEXT PRIMARY KEY,
                    detector_version TEXT NOT NULL,
                    source_digest TEXT NOT NULL,
                    last_sequence_no INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fragment_shingles (
                    fragment_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    sequence_no INTEGER NOT NULL,
                    shingle TEXT NOT NULL,
                    PRIMARY KEY (fragment_id, shingle),
                    FOREIGN KEY (fragment_id) REFERENCES artifact_fragments (fragment_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS information_flow_edge_scopes (
                    edge_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    sequence_no INTEGER NOT NULL,
                    FOREIGN KEY (edge_id) REFERENCES information_flow_edges (edge_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_lineage_state (
                    session_id TEXT NOT NULL,
                    source_node_kind TEXT NOT NULL,
                    source_node_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    best_path_score REAL NOT NULL,
                    predecessor_edge_id TEXT,
                    hop_count INTEGER NOT NULL,
                    updated_sequence_no INTEGER NOT NULL,
                    PRIMARY KEY (
                        session_id,
                        source_node_kind,
                        source_node_id,
                        node_kind,
                        node_id
                    )
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_source_binding_edges (
                    session_id TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    src_node_kind TEXT NOT NULL,
                    src_node_id TEXT NOT NULL,
                    dst_node_kind TEXT NOT NULL,
                    dst_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    evidence_level TEXT NOT NULL,
                    method TEXT NOT NULL,
                    score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY (session_id, edge_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    decision_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    analysis_run_id TEXT NOT NULL,
                    hook_event TEXT,
                    action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    sink_type TEXT NOT NULL,
                    source_node_kind TEXT NOT NULL,
                    source_node_id TEXT NOT NULL,
                    sink_node_id TEXT NOT NULL,
                    path_score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    user_message TEXT NOT NULL,
                    technical_summary TEXT NOT NULL,
                    trace_command TEXT NOT NULL,
                    path_summary_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (analysis_run_id)
                )
                """
            )
            self._initialize_redaction_preview_audit(conn)
            self._migrate_information_flow_edges(conn)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS lineage_assignments (
                    analysis_run_id TEXT NOT NULL,
                    source_node_kind TEXT NOT NULL,
                    source_node_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    best_path_score REAL NOT NULL,
                    predecessor_edge_id TEXT,
                    hop_count INTEGER NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (
                        analysis_run_id,
                        source_node_kind,
                        source_node_id,
                        node_kind,
                        node_id
                    ),
                    FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (analysis_run_id)
                )
                """
            )
            self._migrate_lineage_assignments(conn)
            self._migrate_workspace_analysis_scope(conn)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_tool_use_id ON events (tool_use_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_session_turn ON events (session_id, turn_id)"
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_session_sequence
                ON events (session_id, sequence_no, event_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_workspace_session_sequence
                ON events (workspace_id, session_id, sequence_no, event_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_workspace_status
                ON events (workspace_status, sequence_no, event_id)
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_event_id ON artifacts (event_id)"
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_protected_sources_workspace_key
                ON protected_sources (workspace_id, source_key)
                WHERE workspace_id IS NOT NULL
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_protected_sources_workspace_id
                ON protected_sources (workspace_id, source_id)
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_source_chunks_workspace_ordinal
                ON source_chunks (workspace_id, source_id, ordinal)
                WHERE workspace_id IS NOT NULL
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fragments_artifact_id ON artifact_fragments (artifact_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fragments_text_hash ON artifact_fragments (text_hash)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fragments_operation_id ON artifact_fragments (operation_id)"
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_operations_session_tool
                ON tool_operations (session_id, tool_use_id, operation_index)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_operations_content_fragment
                ON tool_operations (content_fragment_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_operations_event
                ON tool_operations (event_id, operation_index, operation_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_operation_outcomes_operation_event
                ON tool_operation_outcomes (operation_id, post_event_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_resource_snapshots_session_sequence
                ON resource_snapshots (session_id, post_event_id, operation_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_resource_snapshots_session_tool
                ON resource_snapshots (
                    session_id,
                    tool_use_id,
                    operation_id,
                    path_role
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_resource_snapshots_post_event
                ON resource_snapshots (post_event_id, operation_id, path_role)
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_chunks_source_id ON source_chunks (source_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_edges_dst_artifact_id ON flow_edges (dst_artifact_id)"
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_information_flow_edges_src
                ON information_flow_edges (
                    workspace_id,
                    src_node_kind,
                    src_node_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_information_flow_edges_dst
                ON information_flow_edges (
                    workspace_id,
                    dst_node_kind,
                    dst_node_id
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_resource_versions_path "
                "ON resource_versions (workspace_id, path, sequence_no, node_id)"
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_resource_versions_session_sequence
                ON resource_versions (
                    session_id,
                    sequence_no,
                    operation_index,
                    path,
                    node_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_resource_versions_workspace_session
                ON resource_versions (
                    workspace_id,
                    session_id,
                    sequence_no,
                    operation_index,
                    path,
                    node_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sink_candidates_type
                ON sink_candidates (workspace_id, sink_type, node_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sink_candidates_session_sequence
                ON sink_candidates (session_id, sequence_no)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sink_candidates_workspace_session
                ON sink_candidates (
                    workspace_id,
                    session_id,
                    sequence_no,
                    sink_type,
                    node_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_policy_decisions_created
                ON policy_decisions (created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_policy_decisions_analysis_run
                ON policy_decisions (analysis_run_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fragment_shingles_lookup
                ON fragment_shingles (
                    workspace_id,
                    session_id,
                    shingle,
                    sequence_no,
                    fragment_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fragment_exact_lookup
                ON fragment_exact_index (
                    workspace_id,
                    session_id,
                    text_hash,
                    sequence_no DESC,
                    fragment_id DESC
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_edge_scopes_session_sequence
                ON information_flow_edge_scopes (
                    workspace_id,
                    session_id,
                    sequence_no,
                    edge_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_runs_workspace_started
                ON analysis_runs (workspace_id, started_at, analysis_run_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_runs_workspace_session
                ON analysis_runs (
                    workspace_id,
                    session_id,
                    started_at,
                    analysis_run_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_lineage_assignments_run_sink_score
                ON lineage_assignments (
                    analysis_run_id,
                    node_kind,
                    node_id,
                    best_path_score,
                    source_node_kind,
                    source_node_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_run_graphs_workspace
                ON analysis_run_graphs (workspace_id, analysis_run_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_run_nodes_workspace
                ON analysis_run_nodes (
                    workspace_id,
                    analysis_run_id,
                    node_kind
                )
                """
            )
            self._backfill_event_sequence_numbers(conn)
            self._backfill_event_workspaces(conn)
            self._backfill_tool_operation_outcomes(conn)
            conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

    def require_runtime_schema(self) -> None:
        """Validate Hook compatibility without DDL, migration, or backfill."""
        if not self.db_path.is_file():
            raise SchemaCompatibilityError(
                "database_missing",
                "database is not initialized; run 'tooluseproxy init --codex'",
            )
        try:
            uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=0.05) as conn:
                row = conn.execute("PRAGMA user_version").fetchone()
                version = 0 if row is None else int(row[0])
                tables = {
                    item[0]
                    for item in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                columns = {
                    table: {
                        item[1]
                        for item in conn.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()
                    }
                    for table in RUNTIME_REQUIRED_COLUMNS
                    if table in tables
                }
        except sqlite3.Error as exc:
            raise SchemaCompatibilityError(
                "database_unreadable",
                f"database cannot be read: {type(exc).__name__}",
            ) from None
        if version < CURRENT_SCHEMA_VERSION:
            raise SchemaCompatibilityError(
                "schema_upgrade_required",
                "database schema requires 'tooluseproxy init --codex'",
            )
        if version > CURRENT_SCHEMA_VERSION:
            raise SchemaCompatibilityError(
                "schema_too_new",
                "database schema is newer than this ToolUseProxy runtime",
            )
        missing = sorted(RUNTIME_REQUIRED_TABLES - tables)
        if missing:
            raise SchemaCompatibilityError(
                "schema_incomplete",
                f"database schema is incomplete: {', '.join(missing)}",
            )
        incomplete_columns = {
            table: sorted(required - columns.get(table, set()))
            for table, required in RUNTIME_REQUIRED_COLUMNS.items()
            if required - columns.get(table, set())
        }
        if incomplete_columns:
            detail = "; ".join(
                f"{table} missing {', '.join(missing_columns)}"
                for table, missing_columns in sorted(incomplete_columns.items())
            )
            raise SchemaCompatibilityError(
                "schema_incomplete",
                f"database schema is incomplete: {detail}",
            )

    def record(
        self,
        event: NormalizedEvent,
        artifacts: list[ArtifactRecord],
        fragments: list[ArtifactFragment] | None = None,
        operations: list[ToolOperation] | None = None,
        *,
        post_outcome: tuple[str, str] | None = None,
        post_operation_ids: tuple[str, ...] = (),
        resource_snapshots: list[ResourceSnapshot] | None = None,
    ) -> None:
        _validate_event_workspace(event)
        payload_json = json.dumps(
            event.raw_payload,
            ensure_ascii=False,
            sort_keys=True,
        )
        payload_json_bytes = payload_json.encode("utf-8")
        payload_bytes = len(payload_json_bytes)
        payload_sha256 = hashlib.sha256(payload_json_bytes).hexdigest()
        validated_operation_ids = tuple(sorted(set(post_operation_ids)))
        if post_outcome is not None and not validated_operation_ids:
            raise ValueError("post outcome requires validated operation ids")
        if resource_snapshots and any(
            snapshot.post_event_id != event.event_id
            for snapshot in resource_snapshots
        ):
            raise ValueError("resource snapshot post_event_id does not match event")
        if resource_snapshots and not {
            snapshot.operation_id for snapshot in resource_snapshots
        }.issubset(validated_operation_ids):
            raise ValueError("resource snapshot operation is not validated for PostToolUse")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._upsert_workspace_for_event(conn, event)
            existing = conn.execute(
                "SELECT sequence_no FROM events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            sequence_no = (
                existing[0]
                if existing and existing[0] is not None
                else self._next_sequence_no(conn)
            )
            if self._redaction_audit_available is True:
                try:
                    (
                        redaction_event_kind,
                        redaction_scope_sha256,
                        post_input_observation,
                    ) = (
                        _redaction_post_input_observation(
                            event,
                            payload_bytes=payload_bytes,
                        )
                    )
                except Exception:
                    # Optional audit observation must never lose the core event.
                    self._redaction_audit_available = False
                    redaction_event_kind = "not_applicable"
                    redaction_scope_sha256 = None
                    post_input_observation = PostRedactionInputObservation(
                        "not_applicable"
                    )
            else:
                redaction_event_kind = "not_applicable"
                redaction_scope_sha256 = None
                post_input_observation = PostRedactionInputObservation(
                    "not_applicable"
                )
            conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id,
                    phase,
                    session_id,
                    turn_id,
                    tool_use_id,
                    tool_name,
                    cwd,
                    model,
                    permission_mode,
                    transcript_path,
                    stop_hook_active,
                    workspace_id,
                    workspace_root,
                    workspace_lexical_root,
                    workspace_execution_cwd,
                    workspace_status,
                    workspace_source,
                    workspace_namespace_id,
                    payload_json,
                    sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.phase,
                    event.session_id,
                    event.turn_id,
                    event.tool_use_id,
                    event.tool_name,
                    event.cwd,
                    event.model,
                    event.permission_mode,
                    event.transcript_path,
                    (
                        None
                        if event.stop_hook_active is None
                        else int(event.stop_hook_active)
                    ),
                    event.workspace_id,
                    event.workspace_root,
                    event.workspace_lexical_root,
                    event.workspace_execution_cwd,
                    event.workspace_status,
                    event.workspace_source,
                    event.workspace_namespace_id,
                    payload_json,
                    sequence_no,
                ),
            )
            self._record_event_payload_metadata(
                conn,
                event_id=event.event_id,
                payload_bytes=payload_bytes,
                payload_sha256=payload_sha256,
                sequence_no=int(sequence_no),
                redaction_event_kind=redaction_event_kind,
                redaction_scope_sha256=redaction_scope_sha256,
                post_input_observation=post_input_observation,
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id,
                    event_id,
                    role,
                    text,
                    text_hash,
                    normalized_text,
                    token_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        artifact.artifact_id,
                        artifact.event_id,
                        artifact.role,
                        artifact.text,
                        artifact.text_hash,
                        artifact.normalized_text,
                        artifact.token_count,
                    )
                    for artifact in artifacts
                ],
            )
            if operations:
                conn.executemany(
                    """
                    INSERT INTO tool_operations (
                        operation_id,
                        event_id,
                        artifact_id,
                        parent_fragment_id,
                        session_id,
                        tool_use_id,
                        tool_name,
                        adapter,
                        operation_index,
                        operation_kind,
                        source_path,
                        target_path,
                        segment_index,
                        connector,
                        content_fragment_id,
                        outcome,
                        outcome_evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(operation_id) DO UPDATE SET
                        event_id = excluded.event_id,
                        artifact_id = excluded.artifact_id,
                        parent_fragment_id = excluded.parent_fragment_id,
                        session_id = excluded.session_id,
                        tool_use_id = excluded.tool_use_id,
                        tool_name = excluded.tool_name,
                        adapter = excluded.adapter,
                        operation_index = excluded.operation_index,
                        operation_kind = excluded.operation_kind,
                        source_path = excluded.source_path,
                        target_path = excluded.target_path,
                        segment_index = excluded.segment_index,
                        connector = excluded.connector,
                        content_fragment_id = excluded.content_fragment_id
                    """,
                    [_tool_operation_values(operation) for operation in operations],
                )
            if fragments:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO artifact_fragments (
                        fragment_id,
                        artifact_id,
                        json_pointer,
                        semantic_role,
                        text,
                        text_hash,
                        normalized_text,
                        token_count,
                        fragment_kind,
                        parent_fragment_id,
                        operation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            fragment.fragment_id,
                            fragment.artifact_id,
                            fragment.json_pointer,
                            fragment.semantic_role,
                            fragment.text,
                            fragment.text_hash,
                            fragment.normalized_text,
                            fragment.token_count,
                            fragment.fragment_kind,
                            fragment.parent_fragment_id,
                            fragment.operation_id,
                        )
                        for fragment in fragments
                    ],
                )
            if validated_operation_ids:
                self._validate_post_operation_owners(
                    conn,
                    event,
                    validated_operation_ids,
                )
            if post_outcome is not None:
                assert event.session_id is not None and event.tool_use_id is not None
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO tool_operation_outcomes (
                        post_event_id,
                        operation_id,
                        session_id,
                        tool_use_id,
                        outcome,
                        outcome_evidence
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            event.event_id,
                            operation_id,
                            event.session_id,
                            event.tool_use_id,
                            post_outcome[0],
                            post_outcome[1],
                        )
                        for operation_id in validated_operation_ids
                    ],
                )
                placeholders = ",".join("?" for _ in validated_operation_ids)
                conn.execute(
                    f"""
                    UPDATE tool_operations
                    SET outcome = ?, outcome_evidence = ?
                    WHERE operation_id IN ({placeholders})
                    """,
                    (
                        post_outcome[0],
                        post_outcome[1],
                        *validated_operation_ids,
                    ),
                )
            if resource_snapshots:
                if any(
                    snapshot.session_id != event.session_id
                    or snapshot.tool_use_id != event.tool_use_id
                    for snapshot in resource_snapshots
                ):
                    raise ValueError(
                        "resource snapshot session/tool_use does not match event"
                    )
                for snapshot in resource_snapshots:
                    if (
                        snapshot.workspace_root != event.workspace_root
                    ):
                        raise ValueError(
                            "resource snapshot execution context does not match operation owner"
                        )
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO resource_snapshots (
                        snapshot_id,
                        post_event_id,
                        operation_id,
                        session_id,
                        tool_use_id,
                        path_role,
                        requested_path,
                        workspace_root,
                        lexical_path,
                        resource_state,
                        capture_status,
                        file_kind,
                        byte_size,
                        captured_bytes,
                        content_sha256,
                        encoding,
                        body_text,
                        error_code,
                        duration_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        _resource_snapshot_values(snapshot)
                        for snapshot in resource_snapshots
                    ],
                )

    def _validate_post_operation_owners(
        self,
        conn: sqlite3.Connection,
        event: NormalizedEvent,
        operation_ids: tuple[str, ...],
    ) -> None:
        if (
            event.phase != "post_tool_use"
            or event.workspace_status != "ready"
            or event.workspace_id is None
            or event.workspace_root is None
            or event.workspace_execution_cwd is None
            or event.session_id is None
            or event.tool_use_id is None
        ):
            raise ValueError("PostToolUse operation owner requires a ready workspace")
        stored_post = conn.execute(
            """
            SELECT
                phase,
                session_id,
                tool_use_id,
                tool_name,
                workspace_id,
                workspace_root,
                workspace_execution_cwd,
                workspace_status
            FROM events
            WHERE event_id = ?
            """,
            (event.event_id,),
        ).fetchone()
        expected_post = (
            event.phase,
            event.session_id,
            event.tool_use_id,
            event.tool_name,
            event.workspace_id,
            event.workspace_root,
            event.workspace_execution_cwd,
            event.workspace_status,
        )
        if stored_post != expected_post:
            raise ValueError("stored PostToolUse event context does not match")
        placeholders = ",".join("?" for _ in operation_ids)
        rows = conn.execute(
            f"""
            SELECT
                operation.operation_id,
                operation.event_id,
                operation.session_id,
                operation.tool_use_id,
                operation.tool_name,
                owner.phase,
                owner.session_id,
                owner.tool_use_id,
                owner.tool_name,
                owner.workspace_id,
                owner.workspace_root,
                owner.workspace_execution_cwd,
                owner.workspace_status
            FROM tool_operations AS operation
            JOIN events AS owner ON owner.event_id = operation.event_id
            WHERE operation.operation_id IN ({placeholders})
            """,
            operation_ids,
        ).fetchall()
        if {row[0] for row in rows} != set(operation_ids):
            raise ValueError("PostToolUse operation does not exist")
        if len({row[1] for row in rows}) != 1:
            raise ValueError("PostToolUse operation owner is ambiguous")
        for row in rows:
            (
                _,
                _,
                operation_session_id,
                operation_tool_use_id,
                operation_tool_name,
                owner_phase,
                owner_session_id,
                owner_tool_use_id,
                owner_tool_name,
                owner_workspace_id,
                owner_workspace_root,
                owner_execution_cwd,
                owner_workspace_status,
            ) = row
            if (
                owner_phase != "pre_tool_use"
                or owner_workspace_status != "ready"
                or owner_workspace_id != event.workspace_id
                or owner_workspace_root != event.workspace_root
                or owner_execution_cwd != event.workspace_execution_cwd
                or owner_session_id != event.session_id
                or owner_tool_use_id != event.tool_use_id
                or operation_session_id != owner_session_id
                or operation_tool_use_id != owner_tool_use_id
                or _normalized_tool_name(operation_tool_name)
                != _normalized_tool_name(owner_tool_name)
                or _normalized_tool_name(owner_tool_name)
                != _normalized_tool_name(event.tool_name)
            ):
                raise ValueError("PostToolUse operation owner does not match event")

    def list_tool_operations_for_session(
        self,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ToolOperation]:
        clause = "WHERE o.session_id = ?"
        params: tuple[object, ...] = (session_id,)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_tool_operations_where(
            clause,
            params,
            outcome_through_sequence_no=through_sequence_no,
        )

    def list_tool_operations_for_scope(
        self,
        workspace_id: str,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ToolOperation]:
        clause = """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND o.session_id = ?
        """
        params: tuple[object, ...] = (workspace_id, session_id)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_tool_operations_where(
            clause,
            params,
            outcome_through_sequence_no=through_sequence_no,
        )

    def list_tool_operations_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ToolOperation]:
        return self._list_tool_operations_where(
            """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
            """,
            (workspace_id,),
        )

    def list_tool_operations(self) -> list[ToolOperation]:
        return self._list_tool_operations_where("", ())

    def list_tool_operations_for_tool_uses(
        self,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ToolOperation]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"WHERE o.session_id = ? AND o.tool_use_id IN ({placeholders})"
        params: tuple[object, ...] = (session_id, *sorted(tool_use_ids))
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_tool_operations_where(
            clause,
            params,
            outcome_through_sequence_no=through_sequence_no,
        )

    def list_tool_operations_for_scope_tool_uses(
        self,
        workspace_id: str,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ToolOperation]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"""
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND o.session_id = ?
              AND o.tool_use_id IN ({placeholders})
        """
        params: tuple[object, ...] = (
            workspace_id,
            session_id,
            *sorted(tool_use_ids),
        )
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_tool_operations_where(
            clause,
            params,
            outcome_through_sequence_no=through_sequence_no,
        )

    def list_tool_operations_for_post_event(
        self,
        event: NormalizedEvent,
    ) -> list[ToolOperation]:
        if (
            event.phase != "post_tool_use"
            or event.workspace_status != "ready"
            or event.workspace_id is None
            or event.workspace_root is None
            or event.workspace_execution_cwd is None
            or event.session_id is None
            or event.tool_use_id is None
        ):
            return []
        return self._list_tool_operations_where(
            """
            WHERE e.phase = 'pre_tool_use'
              AND e.workspace_status = 'ready'
              AND e.workspace_id = ?
              AND e.workspace_root = ?
              AND e.workspace_execution_cwd = ?
              AND o.session_id = ?
              AND o.tool_use_id = ?
            """,
            (
                event.workspace_id,
                event.workspace_root,
                event.workspace_execution_cwd,
                event.session_id,
                event.tool_use_id,
            ),
        )

    def _list_tool_operations_where(
        self,
        where_clause: str,
        params: tuple[object, ...],
        *,
        outcome_through_sequence_no: int | None = None,
    ) -> list[ToolOperation]:
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    o.operation_id,
                    o.event_id,
                    o.artifact_id,
                    o.parent_fragment_id,
                    o.session_id,
                    o.tool_use_id,
                    o.tool_name,
                    o.adapter,
                    o.operation_index,
                    o.operation_kind,
                    o.source_path,
                    o.target_path,
                    o.segment_index,
                    o.connector,
                    o.content_fragment_id,
                    o.outcome,
                    o.outcome_evidence
                FROM tool_operations AS o
                JOIN events AS e ON e.event_id = o.event_id
                {where_clause}
                ORDER BY e.sequence_no, o.operation_index, o.operation_id
                """,
                params,
            ).fetchall()
            operations = [ToolOperation(*row) for row in rows]
            if not operations:
                return []
            operation_ids = [operation.operation_id for operation in operations]
            placeholders = ",".join("?" for _ in operation_ids)
            outcome_clause = ""
            outcome_params: tuple[object, ...] = tuple(operation_ids)
            if outcome_through_sequence_no is not None:
                outcome_clause = "AND post.sequence_no <= ?"
                outcome_params += (outcome_through_sequence_no,)
            outcome_rows = conn.execute(
                f"""
                SELECT
                    history.operation_id,
                    history.outcome,
                    history.outcome_evidence,
                    history.post_event_id,
                    owned_operation.tool_name,
                    owner.tool_name,
                    post.tool_name
                FROM tool_operation_outcomes AS history
                JOIN tool_operations AS owned_operation
                  ON owned_operation.operation_id = history.operation_id
                JOIN events AS owner ON owner.event_id = owned_operation.event_id
                JOIN events AS post ON post.event_id = history.post_event_id
                WHERE history.operation_id IN ({placeholders})
                  AND owner.phase = 'pre_tool_use'
                  AND post.phase = 'post_tool_use'
                  AND owner.workspace_status = 'ready'
                  AND post.workspace_status = 'ready'
                  AND owner.workspace_id = post.workspace_id
                  AND owner.workspace_root = post.workspace_root
                  AND owner.workspace_execution_cwd = post.workspace_execution_cwd
                  AND owner.session_id IS post.session_id
                  AND owner.tool_use_id IS post.tool_use_id
                  AND owned_operation.session_id IS owner.session_id
                  AND owned_operation.tool_use_id IS owner.tool_use_id
                  AND history.session_id IS owner.session_id
                  AND history.tool_use_id IS owner.tool_use_id
                  {outcome_clause}
                ORDER BY post.sequence_no DESC, history.post_event_id DESC
                """,
                outcome_params,
            ).fetchall()
        latest_outcomes: dict[str, tuple[str, str | None, str]] = {}
        for (
            operation_id,
            outcome,
            evidence,
            post_event_id,
            operation_tool_name,
            owner_tool_name,
            post_tool_name,
        ) in outcome_rows:
            if (
                _normalized_tool_name(operation_tool_name)
                != _normalized_tool_name(owner_tool_name)
                or _normalized_tool_name(owner_tool_name)
                != _normalized_tool_name(post_tool_name)
            ):
                continue
            latest_outcomes.setdefault(
                operation_id,
                (outcome, evidence, post_event_id),
            )
        return [
            replace(
                operation,
                outcome=(
                    latest_outcomes[operation.operation_id][0]
                    if operation.operation_id in latest_outcomes
                    else "unknown"
                ),
                outcome_evidence=(
                    latest_outcomes[operation.operation_id][1]
                    if operation.operation_id in latest_outcomes
                    else None
                ),
                outcome_event_id=(
                    latest_outcomes[operation.operation_id][2]
                    if operation.operation_id in latest_outcomes
                    else None
                ),
            )
            for operation in operations
        ]

    def update_tool_operation_outcome(
        self,
        event: NormalizedEvent,
        operation_ids: tuple[str, ...],
        *,
        outcome: str,
        evidence: str,
        resource_snapshots: list[ResourceSnapshot] | None = None,
    ) -> None:
        normalized_operation_ids = tuple(sorted(set(operation_ids)))
        if not normalized_operation_ids:
            raise ValueError("post outcome requires validated operation ids")
        snapshots = resource_snapshots or []
        if not {snapshot.operation_id for snapshot in snapshots}.issubset(
            normalized_operation_ids
        ):
            raise ValueError("resource snapshot operation is not validated for PostToolUse")
        if any(
            snapshot.post_event_id != event.event_id
            or snapshot.session_id != event.session_id
            or snapshot.tool_use_id != event.tool_use_id
            or snapshot.workspace_root != event.workspace_root
            for snapshot in snapshots
        ):
            raise ValueError("resource snapshot execution context does not match event")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_post_operation_owners(
                conn,
                event,
                normalized_operation_ids,
            )
            assert event.session_id is not None and event.tool_use_id is not None
            conn.executemany(
                """
                INSERT OR REPLACE INTO tool_operation_outcomes (
                    post_event_id,
                    operation_id,
                    session_id,
                    tool_use_id,
                    outcome,
                    outcome_evidence
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        event.event_id,
                        operation_id,
                        event.session_id,
                        event.tool_use_id,
                        outcome,
                        evidence,
                    )
                    for operation_id in normalized_operation_ids
                ],
            )
            placeholders = ",".join("?" for _ in normalized_operation_ids)
            conn.execute(
                f"""
                UPDATE tool_operations
                SET outcome = ?, outcome_evidence = ?
                WHERE operation_id IN ({placeholders})
                """,
                (outcome, evidence, *normalized_operation_ids),
            )
            if snapshots:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO resource_snapshots (
                        snapshot_id,
                        post_event_id,
                        operation_id,
                        session_id,
                        tool_use_id,
                        path_role,
                        requested_path,
                        workspace_root,
                        lexical_path,
                        resource_state,
                        capture_status,
                        file_kind,
                        byte_size,
                        captured_bytes,
                        content_sha256,
                        encoding,
                        body_text,
                        error_code,
                        duration_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [_resource_snapshot_values(snapshot) for snapshot in snapshots],
                )

    def upsert_resource_snapshots(
        self,
        event: NormalizedEvent,
        operation_ids: tuple[str, ...],
        snapshots: list[ResourceSnapshot],
    ) -> None:
        if not snapshots:
            return
        normalized_operation_ids = tuple(sorted(set(operation_ids)))
        if not {snapshot.operation_id for snapshot in snapshots}.issubset(
            normalized_operation_ids
        ):
            raise ValueError("resource snapshot operation is not validated for PostToolUse")
        if any(
            snapshot.post_event_id != event.event_id
            or snapshot.session_id != event.session_id
            or snapshot.tool_use_id != event.tool_use_id
            or snapshot.workspace_root != event.workspace_root
            for snapshot in snapshots
        ):
            raise ValueError("resource snapshot execution context does not match event")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_post_operation_owners(
                conn,
                event,
                normalized_operation_ids,
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO resource_snapshots (
                    snapshot_id,
                    post_event_id,
                    operation_id,
                    session_id,
                    tool_use_id,
                    path_role,
                    requested_path,
                    workspace_root,
                    lexical_path,
                    resource_state,
                    capture_status,
                    file_kind,
                    byte_size,
                    captured_bytes,
                    content_sha256,
                    encoding,
                    body_text,
                    error_code,
                    duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [_resource_snapshot_values(snapshot) for snapshot in snapshots],
            )

    def list_resource_snapshots_for_session(
        self,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ResourceSnapshot]:
        clause = "WHERE s.session_id = ?"
        params: tuple[object, ...] = (session_id,)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_resource_snapshots_where(clause, params)

    def list_resource_snapshots_for_scope(
        self,
        workspace_id: str,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ResourceSnapshot]:
        clause = """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND s.session_id = ?
        """
        params: tuple[object, ...] = (workspace_id, session_id)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_resource_snapshots_where(clause, params)

    def list_resource_snapshots_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ResourceSnapshot]:
        return self._list_resource_snapshots_where(
            """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
            """,
            (workspace_id,),
        )

    def list_resource_snapshots(self) -> list[ResourceSnapshot]:
        return self._list_resource_snapshots_where("", ())

    def list_resource_snapshots_for_tool_uses(
        self,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ResourceSnapshot]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"WHERE s.session_id = ? AND s.tool_use_id IN ({placeholders})"
        params: tuple[object, ...] = (session_id, *sorted(tool_use_ids))
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_resource_snapshots_where(clause, params)

    def list_resource_snapshots_for_scope_tool_uses(
        self,
        workspace_id: str,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ResourceSnapshot]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"""
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND s.session_id = ?
              AND s.tool_use_id IN ({placeholders})
        """
        params: tuple[object, ...] = (
            workspace_id,
            session_id,
            *sorted(tool_use_ids),
        )
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_resource_snapshots_where(clause, params)

    def _list_resource_snapshots_where(
        self,
        where_clause: str,
        params: tuple[object, ...],
    ) -> list[ResourceSnapshot]:
        ownership_clause = """
            owner.phase = 'pre_tool_use'
            AND e.phase = 'post_tool_use'
            AND owner.workspace_status = 'ready'
            AND e.workspace_status = 'ready'
            AND owner.workspace_id = e.workspace_id
            AND owner.workspace_root = e.workspace_root
            AND owner.workspace_execution_cwd = e.workspace_execution_cwd
            AND owner.session_id IS e.session_id
            AND owner.tool_use_id IS e.tool_use_id
            AND operation.session_id IS owner.session_id
            AND operation.tool_use_id IS owner.tool_use_id
            AND s.session_id IS owner.session_id
            AND s.tool_use_id IS owner.tool_use_id
            AND s.workspace_root = owner.workspace_root
        """
        scoped_where_clause = (
            f"{where_clause} AND {ownership_clause}"
            if where_clause
            else f"WHERE {ownership_clause}"
        )
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    s.snapshot_id,
                    s.post_event_id,
                    s.operation_id,
                    s.session_id,
                    s.tool_use_id,
                    s.path_role,
                    s.requested_path,
                    s.workspace_root,
                    s.lexical_path,
                    s.resource_state,
                    s.capture_status,
                    s.file_kind,
                    s.byte_size,
                    s.captured_bytes,
                    s.content_sha256,
                    s.encoding,
                    s.body_text,
                    s.error_code,
                    s.duration_ms,
                    operation.tool_name,
                    owner.tool_name,
                    e.tool_name
                FROM resource_snapshots AS s
                JOIN events AS e ON e.event_id = s.post_event_id
                JOIN tool_operations AS operation
                  ON operation.operation_id = s.operation_id
                JOIN events AS owner ON owner.event_id = operation.event_id
                {scoped_where_clause}
                ORDER BY e.sequence_no, s.operation_id, s.path_role
                """,
                params,
            ).fetchall()
        return [
            ResourceSnapshot(*row[:19])
            for row in rows
            if _normalized_tool_name(row[19]) == _normalized_tool_name(row[20])
            and _normalized_tool_name(row[20]) == _normalized_tool_name(row[21])
        ]

    def upsert_sources(self, sources: list[ProtectedSource], chunks: list[SourceChunk]) -> None:
        if any(
            source.workspace_id is not None or source.source_key is not None
            for source in sources
        ) or any(
            chunk.workspace_id is not None for chunk in chunks
        ):
            raise ValueError(
                "scoped source catalog requires replace_sources_for_workspace"
            )
        _validate_legacy_source_catalog(sources, chunks)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._reject_legacy_source_catalog_collisions(conn, sources, chunks)
            self._write_sources(conn, sources, chunks)

    def replace_sources_for_workspace(
        self,
        workspace_id: str,
        sources: list[ProtectedSource],
        chunks: list[SourceChunk],
    ) -> None:
        _validate_workspace_source_catalog(workspace_id, sources, chunks)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._replace_sources_for_workspace(
                conn,
                workspace_id,
                sources,
                chunks,
            )

    def _replace_sources_for_workspace(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        sources: list[ProtectedSource],
        chunks: list[SourceChunk],
    ) -> None:
        workspace_row = conn.execute(
            "SELECT canonical_root FROM workspaces WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        if workspace_row is None:
            raise ValueError("workspace source catalog requires a registered workspace")
        workspace_root = workspace_row[0]
        for source in sources:
            resolve_protected_source_path(workspace_root, source.path)
        self._reject_cross_workspace_source_catalog_collisions(
            conn,
            workspace_id,
            sources,
            chunks,
        )
        conn.execute(
            "DELETE FROM source_chunks WHERE workspace_id = ?",
            (workspace_id,),
        )
        conn.execute(
            "DELETE FROM protected_sources WHERE workspace_id = ?",
            (workspace_id,),
        )
        self._write_sources(conn, sources, chunks)

    def _reject_legacy_source_catalog_collisions(
        self,
        conn: sqlite3.Connection,
        sources: list[ProtectedSource],
        chunks: list[SourceChunk],
    ) -> None:
        source_ids = [source.source_id for source in sources]
        if source_ids:
            placeholders = ",".join("?" for _ in source_ids)
            if conn.execute(
                f"""
                SELECT 1
                FROM protected_sources
                WHERE source_id IN ({placeholders})
                  AND workspace_id IS NOT NULL
                LIMIT 1
                """,
                source_ids,
            ).fetchone() is not None:
                raise ValueError("legacy source id belongs to a workspace catalog")
        chunk_ids = [chunk.chunk_id for chunk in chunks]
        chunk_source_ids = [chunk.source_id for chunk in chunks]
        if chunk_source_ids:
            placeholders = ",".join("?" for _ in chunk_source_ids)
            if conn.execute(
                f"""
                SELECT 1
                FROM protected_sources
                WHERE source_id IN ({placeholders})
                  AND workspace_id IS NOT NULL
                LIMIT 1
                """,
                chunk_source_ids,
            ).fetchone() is not None:
                raise ValueError(
                    "legacy source chunk references a workspace catalog"
                )
        if chunk_ids:
            placeholders = ",".join("?" for _ in chunk_ids)
            if conn.execute(
                f"""
                SELECT 1
                FROM source_chunks
                WHERE chunk_id IN ({placeholders})
                  AND workspace_id IS NOT NULL
                LIMIT 1
                """,
                chunk_ids,
            ).fetchone() is not None:
                raise ValueError("legacy source chunk id belongs to a workspace catalog")

    def _reject_cross_workspace_source_catalog_collisions(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        sources: list[ProtectedSource],
        chunks: list[SourceChunk],
    ) -> None:
        source_ids = [source.source_id for source in sources]
        if source_ids:
            placeholders = ",".join("?" for _ in source_ids)
            collisions = conn.execute(
                f"""
                SELECT source_id
                FROM protected_sources
                WHERE source_id IN ({placeholders})
                  AND workspace_id IS NOT ?
                LIMIT 1
                """,
                (*source_ids, workspace_id),
            ).fetchone()
            if collisions is not None:
                raise ValueError("protected source id belongs to another workspace")
        chunk_ids = [chunk.chunk_id for chunk in chunks]
        if chunk_ids:
            placeholders = ",".join("?" for _ in chunk_ids)
            collisions = conn.execute(
                f"""
                SELECT chunk_id
                FROM source_chunks
                WHERE chunk_id IN ({placeholders})
                  AND workspace_id IS NOT ?
                LIMIT 1
                """,
                (*chunk_ids, workspace_id),
            ).fetchone()
            if collisions is not None:
                raise ValueError("source chunk id belongs to another workspace")

    def _write_sources(
        self,
        conn: sqlite3.Connection,
        sources: list[ProtectedSource],
        chunks: list[SourceChunk],
    ) -> None:
        conn.executemany(
            """
            INSERT OR REPLACE INTO protected_sources (
                source_id,
                workspace_id,
                source_key,
                path,
                source_type,
                sensitivity,
                policy_tags_json,
                selector_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    source.source_id,
                    source.workspace_id,
                    source.source_key,
                    source.path,
                    source.source_type,
                    source.sensitivity,
                    json.dumps(source.policy_tags, ensure_ascii=False),
                    json.dumps(
                        protected_source_selector_payload(source.selector),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
                for source in sources
            ],
        )
        conn.executemany(
            """
            INSERT OR REPLACE INTO source_chunks (
                chunk_id,
                source_id,
                workspace_id,
                ordinal,
                text,
                normalized_text,
                text_hash,
                shingle_fingerprint,
                token_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    chunk.chunk_id,
                    chunk.source_id,
                    chunk.workspace_id,
                    chunk.ordinal,
                    chunk.text,
                    chunk.normalized_text,
                    chunk.text_hash,
                    chunk.shingle_fingerprint,
                    chunk.token_count,
                )
                for chunk in chunks
            ],
        )

    def upsert_artifact_fragments(self, fragments: list[ArtifactFragment]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO artifact_fragments (
                    fragment_id,
                    artifact_id,
                    json_pointer,
                    semantic_role,
                    text,
                    text_hash,
                    normalized_text,
                    token_count,
                    fragment_kind,
                    parent_fragment_id,
                    operation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        fragment.fragment_id,
                        fragment.artifact_id,
                        fragment.json_pointer,
                        fragment.semantic_role,
                        fragment.text,
                        fragment.text_hash,
                        fragment.normalized_text,
                        fragment.token_count,
                        fragment.fragment_kind,
                        fragment.parent_fragment_id,
                        fragment.operation_id,
                    )
                    for fragment in fragments
                ],
            )

    def insert_artifact_fragments_if_missing(
        self,
        fragments: list[ArtifactFragment],
    ) -> None:
        """Backfill generic fragments without replacing richer derived evidence."""
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO artifact_fragments (
                    fragment_id,
                    artifact_id,
                    json_pointer,
                    semantic_role,
                    text,
                    text_hash,
                    normalized_text,
                    token_count,
                    fragment_kind,
                    parent_fragment_id,
                    operation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        fragment.fragment_id,
                        fragment.artifact_id,
                        fragment.json_pointer,
                        fragment.semantic_role,
                        fragment.text,
                        fragment.text_hash,
                        fragment.normalized_text,
                        fragment.token_count,
                        fragment.fragment_kind,
                        fragment.parent_fragment_id,
                        fragment.operation_id,
                    )
                    for fragment in fragments
                ],
            )

    def start_analysis_run(
        self,
        detector_version: str,
        config: dict[str, object],
        *,
        workspace_id: str | None = None,
        session_id: str | None = None,
    ) -> str:
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id,
                    detector_version,
                    config_json,
                    workspace_id,
                    session_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    analysis_run_id,
                    detector_version,
                    json.dumps(config, ensure_ascii=False, sort_keys=True),
                    workspace_id,
                    session_id,
                ),
            )
        return analysis_run_id

    def start_runtime_analysis_run(
        self,
        detector_version: str,
        config: dict[str, object],
        *,
        workspace_id: str,
        session_id: str,
    ) -> str:
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id,
                    detector_version,
                    config_json,
                    workspace_id,
                    session_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    analysis_run_id,
                    detector_version,
                    json.dumps(config, ensure_ascii=False, sort_keys=True),
                    workspace_id,
                    session_id,
                ),
            )
        return analysis_run_id

    def start_workspace_analysis_run(
        self,
        detector_version: str,
        config: dict[str, object],
        *,
        workspace_id: str,
    ) -> str:
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_registered_workspace(conn, workspace_id)
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id,
                    detector_version,
                    config_json,
                    workspace_id,
                    session_id
                ) VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    analysis_run_id,
                    detector_version,
                    json.dumps(config, ensure_ascii=False, sort_keys=True),
                    workspace_id,
                ),
            )
        return analysis_run_id

    def publish_workspace_analysis_run(
        self,
        *,
        analysis_run_id: str,
        detector_version: str,
        config: dict[str, object],
        workspace_id: str,
        expected_input_revision: str,
        expected_previous_analysis_run_id: str | None,
        expected_analysis_state: dict[str, str | None],
        analysis_state: dict[str, str],
        sources: list[ProtectedSource] | None,
        chunks: list[SourceChunk] | None,
        resources: list[ResourceVersion],
        sinks: list[SinkCandidate],
        artifact_edges: list[FlowEdge],
        source_edges: list[FlowEdge],
        assignments: list[LineageAssignment],
        replace_graph: bool,
        _busy_retry_count: int = 0,
    ) -> str:
        """Atomically promote one fully computed offline workspace analysis."""
        if not isinstance(_busy_retry_count, int) or not 0 <= _busy_retry_count <= 2:
            raise ValueError("offline publish retry count is invalid")
        if re.fullmatch(r"[0-9a-f]{32}", analysis_run_id) is None:
            raise ValueError("offline analysis run id is invalid")
        if not isinstance(detector_version, str) or not detector_version:
            raise ValueError("offline detector version is invalid")
        if _LOWER_SHA256_RE.fullmatch(expected_input_revision) is None:
            raise ValueError("offline analysis input revision is invalid")
        if (sources is None) != (chunks is None):
            raise ValueError("offline source catalog replacement is incomplete")
        if sources is not None and chunks is not None:
            _validate_workspace_source_catalog(workspace_id, sources, chunks)
        if any(resource.workspace_id != workspace_id for resource in resources):
            raise ValueError("resource version workspace does not match publish scope")
        if any(sink.workspace_id != workspace_id for sink in sinks):
            raise ValueError("sink candidate workspace does not match publish scope")
        _validate_node_workspace_owners(
            [(resource.node_id, resource.workspace_id) for resource in resources]
        )
        _validate_node_workspace_owners(
            [(sink.node_id, sink.workspace_id) for sink in sinks]
        )
        if any(
            assignment.analysis_run_id != analysis_run_id
            for assignment in assignments
        ):
            raise ValueError("lineage assignment does not match offline analysis run")
        if (
            not expected_analysis_state
            or set(expected_analysis_state) != set(analysis_state)
            or any(
                not isinstance(key, str) or not key
                for key in expected_analysis_state
            )
            or any(
                value is not None and not isinstance(value, str)
                for value in expected_analysis_state.values()
            )
            or any(not isinstance(value, str) for value in analysis_state.values())
        ):
            raise ValueError("offline analysis state transition is invalid")
        if not replace_graph and expected_analysis_state != analysis_state:
            raise ValueError("reused offline graph cannot change analysis state")
        config_json = json.dumps(config, ensure_ascii=False, sort_keys=True)

        with self._connect() as conn:
            # Hash and CAS against one WAL read snapshot without blocking Hook writers.
            # If another writer commits before the first promote write, SQLite refuses
            # the stale read-to-write upgrade and the whole publication is retried.
            conn.execute("BEGIN")
            self._validate_registered_workspace(conn, workspace_id)
            current_input_revision = self._workspace_analysis_input_revision(
                conn,
                workspace_id,
            )
            if current_input_revision != expected_input_revision:
                raise ValueError("workspace analysis input changed before publish")

            previous_run_row = conn.execute(
                """
                SELECT analysis_run_id
                FROM analysis_runs
                WHERE workspace_id = ?
                  AND session_id IS NULL
                  AND completed_at IS NOT NULL
                ORDER BY started_at DESC, rowid DESC
                LIMIT 1
                """,
                (workspace_id,),
            ).fetchone()
            previous_run_id = None if previous_run_row is None else previous_run_row[0]
            if previous_run_id != expected_previous_analysis_run_id:
                raise ValueError("latest offline analysis run changed before publish")

            for key, expected_value in sorted(expected_analysis_state.items()):
                state_row = conn.execute(
                    """
                    SELECT value
                    FROM workspace_analysis_state
                    WHERE workspace_id = ? AND key = ?
                    """,
                    (workspace_id, key),
                ).fetchone()
                current_value = None if state_row is None else str(state_row[0])
                if current_value != expected_value:
                    raise ValueError("workspace analysis state changed before publish")

            try:
                if sources is not None and chunks is not None:
                    self._replace_sources_for_workspace(
                        conn,
                        workspace_id,
                        sources,
                        chunks,
                    )
                self._replace_resource_versions_for_workspace(
                    conn,
                    workspace_id,
                    resources,
                )
                self._replace_sink_candidates_for_workspace(
                    conn,
                    workspace_id,
                    sinks,
                )
            except sqlite3.OperationalError as exc:
                if _sqlite_is_busy(exc) and _busy_retry_count < 2:
                    conn.rollback()
                    return self.publish_workspace_analysis_run(
                        analysis_run_id=analysis_run_id,
                        detector_version=detector_version,
                        config=config,
                        workspace_id=workspace_id,
                        expected_input_revision=expected_input_revision,
                        expected_previous_analysis_run_id=(
                            expected_previous_analysis_run_id
                        ),
                        expected_analysis_state=expected_analysis_state,
                        analysis_state=analysis_state,
                        sources=sources,
                        chunks=chunks,
                        resources=resources,
                        sinks=sinks,
                        artifact_edges=artifact_edges,
                        source_edges=source_edges,
                        assignments=assignments,
                        replace_graph=replace_graph,
                        _busy_retry_count=_busy_retry_count + 1,
                    )
                raise
            if replace_graph:
                self._replace_information_flow_edges_for_workspace(
                    conn,
                    workspace_id,
                    artifact_edges,
                )
            else:
                self._validate_reused_workspace_graph(
                    conn,
                    workspace_id,
                    artifact_edges,
                )

            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id,
                    detector_version,
                    config_json,
                    workspace_id,
                    session_id
                ) VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    analysis_run_id,
                    detector_version,
                    config_json,
                    workspace_id,
                ),
            )
            self.replace_analysis_run_graph(
                analysis_run_id,
                source_edges + artifact_edges,
                coverage="full",
                _connection=conn,
            )
            self.upsert_source_binding_edges(
                analysis_run_id,
                source_edges,
                _connection=conn,
            )
            self.upsert_lineage_assignments(
                assignments,
                _connection=conn,
            )
            if replace_graph:
                for key, value in sorted(analysis_state.items()):
                    self._set_workspace_analysis_state(
                        conn,
                        workspace_id,
                        key,
                        value,
                    )
            self.complete_analysis_run(
                analysis_run_id,
                _connection=conn,
            )
        return analysis_run_id

    def _validate_reused_workspace_graph(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> None:
        expected: dict[str, tuple[object, ...]] = {}
        for edge in edges:
            values = _flow_edge_values(edge)[1:]
            previous = expected.get(edge.edge_id)
            if previous is not None and previous != values:
                raise ValueError("reused workspace graph has conflicting edge payloads")
            expected[edge.edge_id] = values
        rows = conn.execute(
            """
            SELECT edge_id, src_node_kind, src_node_id,
                   dst_node_kind, dst_node_id, relation,
                   evidence_level, method, score, reason
            FROM information_flow_edges
            WHERE workspace_id = ?
            ORDER BY edge_id
            """,
            (workspace_id,),
        ).fetchall()
        current = {row[0]: tuple(row[1:]) for row in rows}
        if current != expected:
            raise ValueError("reused workspace graph changed before publish")

    def complete_analysis_run(
        self,
        analysis_run_id: str,
        *,
        _connection: sqlite3.Connection | None = None,
    ) -> None:
        owns_connection = _connection is None
        connection_context = (
            self._connect() if owns_connection else nullcontext(_connection)
        )
        with connection_context as conn:
            if owns_connection:
                conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT workspace_id, session_id, completed_at
                FROM analysis_runs
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            ).fetchone()
            if row is None:
                raise ValueError("analysis run does not exist")
            if row[2] is not None:
                return
            workspace_id = row[0]
            if workspace_id is not None:
                self._validate_registered_workspace(conn, workspace_id)
            if workspace_id is not None and row[1] is None:
                graph = conn.execute(
                    """
                    SELECT 1
                    FROM analysis_run_graphs
                    WHERE analysis_run_id = ?
                      AND workspace_id = ?
                      AND node_snapshot_version = 'v1'
                    """,
                    (analysis_run_id, workspace_id),
                ).fetchone()
                if graph is None:
                    raise ValueError(
                        "offline analysis run requires an immutable graph snapshot"
                    )
                missing_node = conn.execute(
                    """
                    SELECT node_kind, node_id
                    FROM (
                        SELECT src_node_kind AS node_kind, src_node_id AS node_id
                        FROM analysis_run_flow_edges
                        WHERE analysis_run_id = ?
                        UNION
                        SELECT dst_node_kind AS node_kind, dst_node_id AS node_id
                        FROM analysis_run_flow_edges
                        WHERE analysis_run_id = ?
                        UNION
                        SELECT src_node_kind AS node_kind, src_node_id AS node_id
                        FROM source_binding_edges
                        WHERE analysis_run_id = ?
                        UNION
                        SELECT dst_node_kind AS node_kind, dst_node_id AS node_id
                        FROM source_binding_edges
                        WHERE analysis_run_id = ?
                        UNION
                        SELECT source_node_kind AS node_kind,
                               source_node_id AS node_id
                        FROM lineage_assignments
                        WHERE analysis_run_id = ?
                        UNION
                        SELECT node_kind, node_id
                        FROM lineage_assignments
                        WHERE analysis_run_id = ?
                    ) AS referenced
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM analysis_run_nodes AS member
                        WHERE member.analysis_run_id = ?
                          AND member.workspace_id = ?
                          AND member.node_kind = referenced.node_kind
                          AND member.node_id = referenced.node_id
                    )
                    LIMIT 1
                    """,
                    (
                        analysis_run_id,
                        analysis_run_id,
                        analysis_run_id,
                        analysis_run_id,
                        analysis_run_id,
                        analysis_run_id,
                        analysis_run_id,
                        workspace_id,
                    ),
                ).fetchone()
                if missing_node is not None:
                    raise ValueError(
                        "offline analysis run references an unsnapshotted node"
                    )
                snapshot_rows = conn.execute(
                    """
                    SELECT
                        member.node_kind,
                        member.node_id,
                        member.snapshot_hash,
                        snapshot.node_kind,
                        snapshot.node_id,
                        snapshot.metadata_json
                    FROM analysis_run_nodes AS member
                    LEFT JOIN analysis_node_snapshots AS snapshot
                      ON snapshot.workspace_id = member.workspace_id
                     AND snapshot.snapshot_hash = member.snapshot_hash
                    WHERE member.analysis_run_id = ?
                      AND member.workspace_id = ?
                    """,
                    (analysis_run_id, workspace_id),
                ).fetchall()
                for (
                    member_kind,
                    member_id,
                    snapshot_hash,
                    snapshot_kind,
                    snapshot_id,
                    metadata_json,
                ) in snapshot_rows:
                    if (
                        snapshot_kind != member_kind
                        or snapshot_id != member_id
                        or metadata_json is None
                        or hashlib.sha256(
                            (
                                f"{member_kind}\0{member_id}\0{metadata_json}"
                            ).encode("utf-8")
                        ).hexdigest()
                        != snapshot_hash
                    ):
                        raise ValueError(
                            "offline analysis run node snapshot is invalid"
                        )
                missing_edge = conn.execute(
                    """
                    SELECT predecessor_edge_id
                    FROM lineage_assignments AS assignment
                    WHERE assignment.analysis_run_id = ?
                      AND assignment.predecessor_edge_id IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1
                          FROM analysis_run_flow_edges AS edge
                          WHERE edge.analysis_run_id = assignment.analysis_run_id
                            AND edge.edge_id = assignment.predecessor_edge_id
                      )
                    LIMIT 1
                    """,
                    (analysis_run_id,),
                ).fetchone()
                if missing_edge is not None:
                    raise ValueError(
                        "offline analysis run references an unsnapshotted edge"
                    )
            conn.execute(
                """
                UPDATE analysis_runs
                SET completed_at = CURRENT_TIMESTAMP
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            )

    def replace_analysis_run_graph(
        self,
        analysis_run_id: str,
        edges: list[FlowEdge],
        *,
        coverage: str = "full",
        _connection: sqlite3.Connection | None = None,
    ) -> None:
        if coverage not in {"full", "lineage"}:
            raise ValueError("analysis run graph coverage is invalid")
        batch: dict[str, tuple[object, ...]] = {}
        for edge in edges:
            if not isinstance(edge.edge_id, str) or not edge.edge_id:
                raise ValueError("analysis run graph contains an invalid edge id")
            values = _flow_edge_values(edge)[1:]
            previous = batch.get(edge.edge_id)
            if previous is not None and previous != values:
                raise ValueError("analysis run edge has conflicting batch payloads")
            batch[edge.edge_id] = values

        owns_connection = _connection is None
        connection_context = (
            self._connect() if owns_connection else nullcontext(_connection)
        )
        with connection_context as conn:
            if owns_connection:
                conn.execute("BEGIN IMMEDIATE")
            run = conn.execute(
                """
                SELECT workspace_id, completed_at
                FROM analysis_runs
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            ).fetchone()
            if run is None or run[0] is None:
                raise ValueError("analysis run graph requires a workspace-scoped run")
            if run[1] is not None:
                raise ValueError("completed analysis run graph is immutable")
            workspace_id = run[0]
            self._validate_registered_workspace(conn, workspace_id)
            marker = conn.execute(
                """
                SELECT workspace_id
                FROM analysis_run_graphs
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            ).fetchone()
            if marker is not None and marker[0] != workspace_id:
                raise ValueError("analysis run graph belongs to another workspace")
            self._validate_analysis_run_graph_node_owners(
                conn,
                workspace_id,
                edges,
            )
            node_snapshots = self._load_analysis_node_snapshot_payloads(
                conn,
                workspace_id,
                edges,
            )
            self._validate_analysis_run_graph_live_edges(
                conn,
                workspace_id,
                batch,
            )
            conn.execute(
                """
                INSERT INTO analysis_run_graphs (
                    analysis_run_id,
                    workspace_id,
                    coverage,
                    node_snapshot_version
                ) VALUES (?, ?, ?, 'v1')
                ON CONFLICT(analysis_run_id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    coverage = excluded.coverage,
                    node_snapshot_version = excluded.node_snapshot_version,
                    recorded_at = CURRENT_TIMESTAMP
                """,
                (analysis_run_id, workspace_id, coverage),
            )
            for (node_kind, node_id), metadata_json in sorted(
                node_snapshots.items()
            ):
                snapshot_hash = hashlib.sha256(
                    (
                        f"{node_kind}\0{node_id}\0{metadata_json}"
                    ).encode("utf-8")
                ).hexdigest()
                existing = conn.execute(
                    """
                    SELECT node_kind, node_id, metadata_json
                    FROM analysis_node_snapshots
                    WHERE workspace_id = ? AND snapshot_hash = ?
                    """,
                    (workspace_id, snapshot_hash),
                ).fetchone()
                if existing is not None and existing != (
                    node_kind,
                    node_id,
                    metadata_json,
                ):
                    raise ValueError("analysis node snapshot hash collision")
                conn.execute(
                    """
                    INSERT OR IGNORE INTO analysis_node_snapshots (
                        workspace_id,
                        snapshot_hash,
                        node_kind,
                        node_id,
                        metadata_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id,
                        snapshot_hash,
                        node_kind,
                        node_id,
                        metadata_json,
                    ),
                )
            conn.execute(
                """
                DELETE FROM analysis_run_nodes
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            )
            conn.executemany(
                """
                INSERT INTO analysis_run_nodes (
                    analysis_run_id,
                    workspace_id,
                    node_kind,
                    node_id,
                    snapshot_hash
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        analysis_run_id,
                        workspace_id,
                        node_kind,
                        node_id,
                        hashlib.sha256(
                            (
                                f"{node_kind}\0{node_id}\0"
                                f"{node_snapshots[(node_kind, node_id)]}"
                            ).encode("utf-8")
                        ).hexdigest(),
                    )
                    for node_kind, node_id in sorted(node_snapshots)
                ],
            )
            conn.execute(
                """
                DELETE FROM analysis_run_flow_edges
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            )
            conn.executemany(
                """
                INSERT INTO analysis_run_flow_edges (
                    analysis_run_id,
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (analysis_run_id, edge_id, *values)
                    for edge_id, values in sorted(batch.items())
                ],
            )

    def _validate_analysis_run_graph_node_owners(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> None:
        self._validate_analysis_node_owners(
            conn,
            workspace_id,
            [
                node
                for edge in edges
                for node in (
                    (edge.src_node_kind, edge.src_node_id),
                    (edge.dst_node_kind, edge.dst_node_id),
                )
            ],
        )

    def _validate_analysis_node_owners(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        nodes: list[tuple[str, str]],
    ) -> None:
        node_ids_by_kind: dict[str, set[str]] = {
            "artifact_fragment": set(),
            "protected_source": set(),
            "source_chunk": set(),
            "resource_version": set(),
            "sink_candidate": set(),
        }
        for node_kind, node_id in nodes:
            if node_kind not in node_ids_by_kind:
                raise ValueError("analysis run graph contains an unknown node kind")
            if not isinstance(node_id, str) or not node_id:
                raise ValueError("analysis run graph contains an invalid node id")
            node_ids_by_kind[node_kind].add(node_id)

        ownership_queries = {
            "artifact_fragment": """
                SELECT f.fragment_id
                FROM artifact_fragments AS f
                JOIN artifacts AS a ON a.artifact_id = f.artifact_id
                JOIN events AS e ON e.event_id = a.event_id
                WHERE f.fragment_id IN ({placeholders})
                  AND e.workspace_id = ?
                  AND e.workspace_status = 'ready'
            """,
            "protected_source": """
                SELECT source_id
                FROM protected_sources
                WHERE source_id IN ({placeholders})
                  AND workspace_id = ?
            """,
            "source_chunk": """
                SELECT c.chunk_id
                FROM source_chunks AS c
                JOIN protected_sources AS source
                  ON source.source_id = c.source_id
                WHERE c.chunk_id IN ({placeholders})
                  AND c.workspace_id = ?
                  AND source.workspace_id = ?
            """,
            "resource_version": """
                SELECT node_id
                FROM resource_versions
                WHERE node_id IN ({placeholders})
                  AND workspace_id = ?
            """,
            "sink_candidate": """
                SELECT node_id
                FROM sink_candidates
                WHERE node_id IN ({placeholders})
                  AND workspace_id = ?
            """,
        }
        multi_owner_tables = {
            "resource_version": "resource_versions",
            "sink_candidate": "sink_candidates",
        }
        for node_kind, node_ids in node_ids_by_kind.items():
            ordered_ids = sorted(node_ids)
            for start in range(0, len(ordered_ids), 300):
                current_ids = ordered_ids[start:start + 300]
                placeholders = ",".join("?" for _ in current_ids)
                query = ownership_queries[node_kind].format(
                    placeholders=placeholders,
                )
                params: tuple[object, ...] = (*current_ids, workspace_id)
                if node_kind == "source_chunk":
                    params += (workspace_id,)
                found = {
                    row[0]
                    for row in conn.execute(query, params).fetchall()
                }
                if found != set(current_ids):
                    raise ValueError(
                        "analysis run graph node is missing or belongs to "
                        "another workspace"
                    )
                owner_table = multi_owner_tables.get(node_kind)
                if owner_table is not None:
                    collision = conn.execute(
                        f"""
                        SELECT 1
                        FROM {owner_table}
                        WHERE node_id IN ({placeholders})
                          AND workspace_id IS NOT ?
                        LIMIT 1
                        """,
                        (*current_ids, workspace_id),
                    ).fetchone()
                    if collision is not None:
                        raise ValueError(
                            "analysis run graph node has multiple workspace owners"
                        )

    def _load_analysis_node_snapshot_payloads(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> dict[tuple[str, str], str]:
        node_ids_by_kind: dict[str, set[str]] = {}
        for edge in edges:
            for node_kind, node_id in (
                (edge.src_node_kind, edge.src_node_id),
                (edge.dst_node_kind, edge.dst_node_id),
            ):
                node_ids_by_kind.setdefault(node_kind, set()).add(node_id)

        source_chunk_ids = sorted(node_ids_by_kind.get("source_chunk", set()))
        for start in range(0, len(source_chunk_ids), 300):
            current_ids = source_chunk_ids[start:start + 300]
            placeholders = ",".join("?" for _ in current_ids)
            parent_source_ids = {
                row[0]
                for row in conn.execute(
                    f"""
                    SELECT source_id
                    FROM source_chunks
                    WHERE chunk_id IN ({placeholders})
                      AND workspace_id = ?
                    """,
                    (*current_ids, workspace_id),
                ).fetchall()
            }
            node_ids_by_kind.setdefault("protected_source", set()).update(
                parent_source_ids
            )

        snapshots: dict[tuple[str, str], str] = {}
        for node_kind, node_ids in node_ids_by_kind.items():
            ordered_ids = sorted(node_ids)
            for start in range(0, len(ordered_ids), 300):
                current_ids = ordered_ids[start:start + 300]
                placeholders = ",".join("?" for _ in current_ids)
                if node_kind == "artifact_fragment":
                    rows = conn.execute(
                        f"""
                        SELECT
                            f.fragment_id,
                            f.artifact_id,
                            f.json_pointer,
                            f.semantic_role,
                            f.text,
                            f.text_hash,
                            f.normalized_text,
                            f.token_count,
                            f.fragment_kind,
                            f.parent_fragment_id,
                            f.operation_id,
                            a.role,
                            e.event_id,
                            e.phase,
                            e.session_id,
                            e.turn_id,
                            e.tool_use_id,
                            e.tool_name,
                            e.cwd,
                            e.sequence_no,
                            e.workspace_id,
                            e.workspace_root,
                            e.workspace_lexical_root,
                            e.workspace_execution_cwd,
                            e.workspace_status
                        FROM artifact_fragments AS f
                        JOIN artifacts AS a ON a.artifact_id = f.artifact_id
                        JOIN events AS e ON e.event_id = a.event_id
                        WHERE f.fragment_id IN ({placeholders})
                          AND e.workspace_id = ?
                          AND e.workspace_status = 'ready'
                        """,
                        (*current_ids, workspace_id),
                    ).fetchall()
                    payloads = [
                        (
                            row[0],
                            {
                                "fragment": {
                                    "fragment_id": row[0],
                                    "artifact_id": row[1],
                                    "json_pointer": row[2],
                                    "semantic_role": row[3],
                                    "text": row[4],
                                    "text_hash": row[5],
                                    "normalized_text": row[6],
                                    "token_count": row[7],
                                    "fragment_kind": row[8],
                                    "parent_fragment_id": row[9],
                                    "operation_id": row[10],
                                },
                                "artifact_role": row[11],
                                "event_id": row[12],
                                "phase": row[13],
                                "session_id": row[14],
                                "turn_id": row[15],
                                "tool_use_id": row[16],
                                "tool_name": row[17],
                                "cwd": row[18],
                                "sequence_no": row[19],
                                "workspace_id": row[20],
                                "workspace_root": row[21],
                                "workspace_lexical_root": row[22],
                                "workspace_execution_cwd": row[23],
                                "workspace_status": row[24],
                            },
                        )
                        for row in rows
                    ]
                elif node_kind == "protected_source":
                    rows = conn.execute(
                        f"""
                        SELECT source_id, path, source_type, sensitivity,
                               policy_tags_json, workspace_id, source_key,
                               selector_json
                        FROM protected_sources
                        WHERE source_id IN ({placeholders})
                          AND workspace_id = ?
                        """,
                        (*current_ids, workspace_id),
                    ).fetchall()
                    payloads = [
                        (
                            row[0],
                            {
                                "source_id": row[0],
                                "path": row[1],
                                "source_type": row[2],
                                "sensitivity": row[3],
                                "policy_tags": json.loads(row[4]),
                                "workspace_id": row[5],
                                "source_key": row[6],
                                "selector": json.loads(row[7]),
                            },
                        )
                        for row in rows
                    ]
                elif node_kind == "source_chunk":
                    rows = conn.execute(
                        f"""
                        SELECT chunk_id, source_id, ordinal, text,
                               normalized_text, text_hash, shingle_fingerprint,
                               token_count, workspace_id
                        FROM source_chunks
                        WHERE chunk_id IN ({placeholders})
                          AND workspace_id = ?
                        """,
                        (*current_ids, workspace_id),
                    ).fetchall()
                    payloads = [
                        (
                            row[0],
                            {
                                "chunk_id": row[0],
                                "source_id": row[1],
                                "ordinal": row[2],
                                "text": row[3],
                                "normalized_text": row[4],
                                "text_hash": row[5],
                                "shingle_fingerprint": row[6],
                                "token_count": row[7],
                                "workspace_id": row[8],
                            },
                        )
                        for row in rows
                    ]
                elif node_kind == "resource_version":
                    rows = conn.execute(
                        f"""
                        SELECT node_id, path, content_hash, sequence_no,
                               session_id, origin_tool_use_id, operation_id,
                               operation_index, snapshot_id, resource_state,
                               workspace_id
                        FROM resource_versions
                        WHERE node_id IN ({placeholders})
                          AND workspace_id = ?
                        """,
                        (*current_ids, workspace_id),
                    ).fetchall()
                    payloads = [
                        (
                            row[0],
                            {
                                "node_id": row[0],
                                "path": row[1],
                                "content_hash": row[2],
                                "sequence_no": row[3],
                                "session_id": row[4],
                                "origin_tool_use_id": row[5],
                                "operation_id": row[6],
                                "operation_index": row[7],
                                "snapshot_id": row[8],
                                "resource_state": row[9],
                                "workspace_id": row[10],
                            },
                        )
                        for row in rows
                    ]
                elif node_kind == "sink_candidate":
                    rows = conn.execute(
                        f"""
                        SELECT node_id, sink_type, label, tool_name,
                               tool_use_id, session_id, sequence_no,
                               metadata_json, workspace_id
                        FROM sink_candidates
                        WHERE node_id IN ({placeholders})
                          AND workspace_id = ?
                        """,
                        (*current_ids, workspace_id),
                    ).fetchall()
                    payloads = [
                        (
                            row[0],
                            {
                                "node_id": row[0],
                                "sink_type": row[1],
                                "label": row[2],
                                "tool_name": row[3],
                                "tool_use_id": row[4],
                                "session_id": row[5],
                                "sequence_no": row[6],
                                "metadata": json.loads(row[7]),
                                "workspace_id": row[8],
                            },
                        )
                        for row in rows
                    ]
                else:
                    raise ValueError("analysis run graph contains an unknown node kind")

                for node_id, payload in payloads:
                    snapshots[(node_kind, node_id)] = json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )

        expected = {
            (node_kind, node_id)
            for node_kind, node_ids in node_ids_by_kind.items()
            for node_id in node_ids
        }
        if set(snapshots) != expected:
            raise ValueError("analysis run node snapshot is incomplete")
        return snapshots

    def _validate_analysis_run_graph_live_edges(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        batch: dict[str, tuple[object, ...]],
    ) -> None:
        edge_ids = sorted(batch)
        for start in range(0, len(edge_ids), 300):
            current_ids = edge_ids[start:start + 300]
            placeholders = ",".join("?" for _ in current_ids)
            rows = conn.execute(
                f"""
                SELECT
                    edge_id,
                    workspace_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                FROM information_flow_edges
                WHERE edge_id IN ({placeholders})
                """,
                current_ids,
            ).fetchall()
            for row in rows:
                edge_id = row[0]
                if row[1] != workspace_id:
                    raise ValueError("analysis run edge belongs to another workspace")
                if tuple(row[2:]) != batch[edge_id]:
                    raise ValueError("analysis run edge conflicts with live graph payload")

    def has_analysis_run_graph(self, analysis_run_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM analysis_run_graphs AS graph
                JOIN analysis_runs AS run
                  ON run.analysis_run_id = graph.analysis_run_id
                 AND run.workspace_id = graph.workspace_id
                WHERE graph.analysis_run_id = ?
                  AND run.workspace_id IS NOT NULL
                """,
                (analysis_run_id,),
            ).fetchone()
        return row is not None

    def get_analysis_run_graph_coverage(
        self,
        analysis_run_id: str,
    ) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT graph.coverage
                FROM analysis_run_graphs AS graph
                JOIN analysis_runs AS run
                  ON run.analysis_run_id = graph.analysis_run_id
                 AND run.workspace_id = graph.workspace_id
                WHERE graph.analysis_run_id = ?
                  AND run.workspace_id IS NOT NULL
                """,
                (analysis_run_id,),
            ).fetchone()
        return None if row is None else row[0]

    def has_analysis_run_node_snapshot(self, analysis_run_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM analysis_run_graphs AS graph
                JOIN analysis_runs AS run
                  ON run.analysis_run_id = graph.analysis_run_id
                 AND run.workspace_id = graph.workspace_id
                WHERE graph.analysis_run_id = ?
                  AND graph.node_snapshot_version = 'v1'
                  AND run.workspace_id IS NOT NULL
                """,
                (analysis_run_id,),
            ).fetchone()
        return row is not None

    def list_analysis_run_node_snapshots(
        self,
        analysis_run_id: str,
        node_kind: str,
    ) -> list[dict[str, object]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    member.node_kind,
                    member.node_id,
                    member.snapshot_hash,
                    snapshot.metadata_json
                FROM analysis_run_nodes AS member
                JOIN analysis_run_graphs AS graph
                  ON graph.analysis_run_id = member.analysis_run_id
                 AND graph.workspace_id = member.workspace_id
                JOIN analysis_runs AS run
                  ON run.analysis_run_id = graph.analysis_run_id
                 AND run.workspace_id = graph.workspace_id
                JOIN analysis_node_snapshots AS snapshot
                  ON snapshot.workspace_id = member.workspace_id
                 AND snapshot.snapshot_hash = member.snapshot_hash
                 AND snapshot.node_kind = member.node_kind
                 AND snapshot.node_id = member.node_id
                WHERE member.analysis_run_id = ?
                  AND member.node_kind = ?
                  AND graph.node_snapshot_version = 'v1'
                  AND run.workspace_id IS NOT NULL
                ORDER BY member.node_id
                """,
                (analysis_run_id, node_kind),
            ).fetchall()
        payloads: list[dict[str, object]] = []
        for stored_kind, node_id, snapshot_hash, metadata_json in rows:
            expected_hash = hashlib.sha256(
                f"{stored_kind}\0{node_id}\0{metadata_json}".encode("utf-8")
            ).hexdigest()
            if expected_hash != snapshot_hash:
                raise ValueError("analysis node snapshot hash does not match payload")
            payload = json.loads(metadata_json)
            if not isinstance(payload, dict):
                raise ValueError("analysis node snapshot payload is invalid")
            payloads.append(payload)
        return payloads

    def list_analysis_run_flow_edges(
        self,
        analysis_run_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    edge.edge_id,
                    edge.src_node_kind,
                    edge.src_node_id,
                    edge.dst_node_kind,
                    edge.dst_node_id,
                    edge.relation,
                    edge.evidence_level,
                    edge.method,
                    edge.score,
                    edge.reason
                FROM analysis_run_flow_edges AS edge
                JOIN analysis_run_graphs AS graph
                  ON graph.analysis_run_id = edge.analysis_run_id
                JOIN analysis_runs AS run
                  ON run.analysis_run_id = graph.analysis_run_id
                 AND run.workspace_id = graph.workspace_id
                WHERE edge.analysis_run_id = ?
                  AND run.workspace_id IS NOT NULL
                ORDER BY edge.edge_id
                """,
                (analysis_run_id,),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def upsert_policy_decision(self, decision: StoredPolicyDecision) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policy_decisions (
                    decision_id,
                    finding_id,
                    analysis_run_id,
                    hook_event,
                    action,
                    severity,
                    sink_type,
                    source_node_kind,
                    source_node_id,
                    sink_node_id,
                    path_score,
                    reason,
                    user_message,
                    technical_summary,
                    trace_command,
                    path_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(decision_id) DO UPDATE SET
                    finding_id = excluded.finding_id,
                    analysis_run_id = excluded.analysis_run_id,
                    hook_event = excluded.hook_event,
                    action = excluded.action,
                    severity = excluded.severity,
                    sink_type = excluded.sink_type,
                    source_node_kind = excluded.source_node_kind,
                    source_node_id = excluded.source_node_id,
                    sink_node_id = excluded.sink_node_id,
                    path_score = excluded.path_score,
                    reason = excluded.reason,
                    user_message = excluded.user_message,
                    technical_summary = excluded.technical_summary,
                    trace_command = excluded.trace_command,
                    path_summary_json = excluded.path_summary_json
                """,
                (
                    decision.decision_id,
                    decision.finding_id,
                    decision.analysis_run_id,
                    decision.hook_event,
                    decision.action,
                    decision.severity,
                    decision.sink_type,
                    decision.source_node_kind,
                    decision.source_node_id,
                    decision.sink_node_id,
                    decision.path_score,
                    decision.reason,
                    decision.user_message,
                    decision.technical_summary,
                    decision.trace_command,
                    json.dumps(decision.path_summary, ensure_ascii=False),
                ),
            )

    def list_policy_decisions(self, limit: int = 20) -> list[StoredPolicyDecision]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    decision_id,
                    finding_id,
                    analysis_run_id,
                    hook_event,
                    action,
                    severity,
                    sink_type,
                    source_node_kind,
                    source_node_id,
                    sink_node_id,
                    path_score,
                    reason,
                    user_message,
                    technical_summary,
                    trace_command,
                    path_summary_json,
                    created_at
                FROM policy_decisions
                ORDER BY created_at DESC, decision_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_stored_policy_decision_from_row(row) for row in rows]

    def get_policy_decision(
        self,
        decision_id: str,
    ) -> StoredPolicyDecision | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    decision_id,
                    finding_id,
                    analysis_run_id,
                    hook_event,
                    action,
                    severity,
                    sink_type,
                    source_node_kind,
                    source_node_id,
                    sink_node_id,
                    path_score,
                    reason,
                    user_message,
                    technical_summary,
                    trace_command,
                    path_summary_json,
                    created_at
                FROM policy_decisions
                WHERE decision_id = ?
                """,
                (decision_id,),
            ).fetchone()
        return None if row is None else _stored_policy_decision_from_row(row)

    def upsert_redaction_plan(self, plan: StoredRedactionPlan) -> None:
        """Insert one immutable plan and all targets, or verify an exact replay."""
        if self._redaction_audit_available is not True:
            raise RuntimeError("redaction preview audit schema is unavailable")
        _validate_stored_redaction_plan(plan)
        plan_values = _redaction_plan_values(plan)
        target_values = tuple(_redaction_target_values(target) for target in plan.targets)
        with self._connect_redaction_audit() as conn:
            # Hold one WAL snapshot while replaying, then upgrade only for the
            # small atomic plan/target insert. A concurrent writer may make the
            # upgrade fail fast; the caller keeps the already-rendered deny.
            conn.execute("BEGIN")
            event_sequence_no, event, analysis_run = (
                self._validate_redaction_plan_owner(conn, plan)
            )
            existing = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_VALUE_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ?
                """,
                (plan.plan_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != plan_values:
                    raise ValueError("redaction plan is immutable")
                existing_targets = tuple(
                    conn.execute(
                        f"""
                        SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                        FROM redaction_targets
                        WHERE plan_id = ?
                        ORDER BY ordinal
                        """,
                        (plan.plan_id,),
                    ).fetchall()
                )
                if existing_targets != target_values:
                    raise ValueError("redaction plan targets are immutable")
                return

            collision = conn.execute(
                """
                SELECT plan_id
                FROM redaction_plans
                WHERE workspace_id = ?
                  AND pre_event_id = ?
                  AND analysis_run_id = ?
                  AND planner_version = ?
                  AND profile_version = ?
                  AND mode = ?
                """,
                (
                    plan.workspace_id,
                    plan.pre_event_id,
                    plan.analysis_run_id,
                    plan.planner_version,
                    plan.profile_version,
                    plan.mode,
                ),
            ).fetchone()
            if collision is not None:
                raise ValueError("redaction plan identity maps to a different plan id")
            self._validate_redaction_plan_replay(
                conn,
                plan,
                event_sequence_no,
                event,
                analysis_run,
            )
            conn.execute(
                """
                INSERT INTO redaction_plans (
                    plan_id,
                    analysis_run_id,
                    pre_event_id,
                    workspace_id,
                    session_id,
                    tool_use_id,
                    tool_name,
                    adapter,
                    profile_id,
                    profile_version,
                    profile_registry_version,
                    mode,
                    status,
                    planner_version,
                    original_input_sha256,
                    rewritten_input_sha256,
                    structure_sha256_before,
                    structure_sha256_after,
                    critical_finding_count,
                    replacement_count,
                    rejection_code,
                    post_event_id,
                    rendered_at,
                    confirmed_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                plan_values,
            )
            conn.executemany(
                """
                INSERT INTO redaction_targets (
                    plan_id,
                    ordinal,
                    finding_id,
                    decision_id,
                    source_node_kind,
                    source_node_id,
                    sink_node_id,
                    json_pointer,
                    original_value_sha256,
                    replacement_profile
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                target_values,
            )

    def get_redaction_plan(
        self,
        plan_id: str,
        *,
        workspace_id: str,
    ) -> StoredRedactionPlan | None:
        if not plan_id or not workspace_id:
            raise ValueError("redaction plan lookup requires plan and workspace ids")
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_SELECT_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ? AND workspace_id = ?
                """,
                (plan_id, workspace_id),
            ).fetchone()
            if row is None:
                return None
            targets = conn.execute(
                f"""
                SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                FROM redaction_targets
                WHERE plan_id = ?
                ORDER BY ordinal
                """,
                (plan_id,),
            ).fetchall()
        return _stored_redaction_plan_from_rows(row, targets)

    def list_redaction_plans(
        self,
        *,
        workspace_id: str,
        session_id: str | None = None,
        tool_use_id: str | None = None,
        limit: int = 20,
    ) -> list[StoredRedactionPlan]:
        if not workspace_id:
            raise ValueError("redaction plan lookup requires a workspace id")
        if session_id is not None and not session_id:
            raise ValueError("redaction plan session filter must not be empty")
        if tool_use_id is not None and not tool_use_id:
            raise ValueError("redaction plan tool-use filter must not be empty")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("redaction plan limit must be between 1 and 1000")
        clauses = ["workspace_id = ?"]
        params: list[object] = [workspace_id]
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if tool_use_id is not None:
            clauses.append("tool_use_id = ?")
            params.append(tool_use_id)
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_SELECT_COLUMNS}
                FROM redaction_plans
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, plan_id
                LIMIT ?
                """,
                params,
            ).fetchall()
            plans: list[StoredRedactionPlan] = []
            for row in rows:
                targets = conn.execute(
                    f"""
                    SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                    FROM redaction_targets
                    WHERE plan_id = ?
                    ORDER BY ordinal
                    """,
                    (row[0],),
                ).fetchall()
                plans.append(_stored_redaction_plan_from_rows(row, targets))
        return plans

    def prepare_redaction_enforcement(
        self,
        preview_plan_id: str,
        *,
        workspace_id: str,
    ) -> StoredRedactionPlan:
        """Atomically prepare the audit half of a future MCP renderer.

        No current runtime calls this method and it never produces Hook output.
        A future renderer may proceed only after this exact, all-finding clone
        and its derived-decision links have been committed.
        """
        if self._redaction_audit_available is not True:
            raise RuntimeError("redaction preview audit schema is unavailable")
        if (
            not isinstance(preview_plan_id, str)
            or _LOWER_SHA256_RE.fullmatch(preview_plan_id) is None
            or not _bounded_audit_identifier(workspace_id)
        ):
            raise ValueError(
                "redaction enforcement requires bounded plan and workspace ids"
            )

        with self._connect_redaction_audit() as conn:
            # Core storage still has legacy INSERT OR REPLACE paths that are
            # not ready for process-wide FK enforcement. Require it only for
            # this new ownership graph before starting the atomic writer.
            conn.execute("PRAGMA foreign_keys = ON")
            if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise RuntimeError(
                    "redaction enforcement foreign keys are unavailable"
                )
            # Replay under one WAL snapshot. Upgrade only after the bounded
            # deterministic validation so a contended writer fails fast and a
            # caller can keep its already-computed BLOCK output.
            conn.execute("BEGIN")
            preview_row = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_SELECT_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ?
                  AND workspace_id = ?
                  AND mode = 'preview'
                  AND status = 'eligible'
                """,
                (preview_plan_id, workspace_id),
            ).fetchone()
            if preview_row is None:
                raise ValueError(
                    "redaction enforcement requires one eligible preview"
                )
            preview_target_rows = conn.execute(
                f"""
                SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                FROM redaction_targets
                WHERE plan_id = ?
                ORDER BY ordinal
                LIMIT ?
                """,
                (
                    preview_plan_id,
                    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                ),
            ).fetchall()
            if (
                not preview_target_rows
                or len(preview_target_rows)
                > REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
            ):
                raise ValueError("redaction enforcement target limit exceeded")
            preview = _stored_redaction_plan_from_rows(
                preview_row,
                preview_target_rows,
            )
            _validate_stored_redaction_plan(preview)
            event_sequence_no, event, analysis_run = (
                self._validate_redaction_plan_owner(conn, preview)
            )
            self._validate_redaction_plan_replay(
                conn,
                preview,
                event_sequence_no,
                event,
                analysis_run,
            )

            enforce_plan_id = _redaction_plan_id_for_mode(preview, "enforce")
            enforce_targets = tuple(
                replace(target, plan_id=enforce_plan_id)
                for target in preview.targets
            )
            enforce = replace(
                preview,
                plan_id=enforce_plan_id,
                mode="enforce",
                status="eligible",
                post_event_id=None,
                targets=enforce_targets,
                created_at=None,
                rendered_at=None,
                confirmed_at=None,
            )
            links = tuple(
                _make_redaction_decision_link(
                    enforce_plan_id=enforce.plan_id,
                    preview_plan_id=preview.plan_id,
                    target=target,
                )
                for target in enforce.targets
            )
            _validate_prepared_redaction_enforcement(
                preview=preview,
                enforce=enforce,
                links=links,
            )

            existing_row = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_SELECT_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ?
                """,
                (enforce_plan_id,),
            ).fetchone()
            if existing_row is not None:
                existing_target_rows = conn.execute(
                    f"""
                    SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                    FROM redaction_targets
                    WHERE plan_id = ?
                    ORDER BY ordinal
                    LIMIT ?
                    """,
                    (
                        enforce_plan_id,
                        REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                    ),
                ).fetchall()
                existing_link_rows = conn.execute(
                    f"""
                    SELECT {_REDACTION_DECISION_LINK_SELECT_COLUMNS}
                    FROM redaction_decision_links
                    WHERE enforce_plan_id = ?
                    ORDER BY target_ordinal
                    LIMIT ?
                    """,
                    (
                        enforce_plan_id,
                        REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                    ),
                ).fetchall()
                existing = _stored_redaction_plan_from_rows(
                    existing_row,
                    existing_target_rows,
                )
                stored_links = tuple(
                    _stored_redaction_decision_link_from_row(row)
                    for row in existing_link_rows
                )
                if not _prepared_redaction_enforcement_matches(
                    expected=enforce,
                    actual=existing,
                    expected_links=links,
                    actual_links=stored_links,
                ):
                    raise ValueError("redaction enforcement audit is immutable")
                return existing

            collision = conn.execute(
                """
                SELECT plan_id
                FROM redaction_plans
                WHERE workspace_id = ?
                  AND pre_event_id = ?
                  AND analysis_run_id = ?
                  AND planner_version = ?
                  AND profile_version = ?
                  AND mode = 'enforce'
                """,
                (
                    enforce.workspace_id,
                    enforce.pre_event_id,
                    enforce.analysis_run_id,
                    enforce.planner_version,
                    enforce.profile_version,
                ),
            ).fetchone()
            linkage_collision = conn.execute(
                """
                SELECT 1
                FROM redaction_decision_links
                WHERE enforce_plan_id = ? OR preview_plan_id = ?
                LIMIT 1
                """,
                (enforce.plan_id, preview.plan_id),
            ).fetchone()
            if collision is not None or linkage_collision is not None:
                raise ValueError("redaction enforcement identity collision")

            conn.execute(
                """
                INSERT INTO redaction_plans (
                    plan_id,
                    analysis_run_id,
                    pre_event_id,
                    workspace_id,
                    session_id,
                    tool_use_id,
                    tool_name,
                    adapter,
                    profile_id,
                    profile_version,
                    profile_registry_version,
                    mode,
                    status,
                    planner_version,
                    original_input_sha256,
                    rewritten_input_sha256,
                    structure_sha256_before,
                    structure_sha256_after,
                    critical_finding_count,
                    replacement_count,
                    rejection_code,
                    post_event_id,
                    rendered_at,
                    confirmed_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                _redaction_plan_values(enforce),
            )
            conn.executemany(
                """
                INSERT INTO redaction_targets (
                    plan_id,
                    ordinal,
                    finding_id,
                    decision_id,
                    source_node_kind,
                    source_node_id,
                    sink_node_id,
                    json_pointer,
                    original_value_sha256,
                    replacement_profile
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(_redaction_target_values(target) for target in enforce.targets),
            )
            conn.executemany(
                """
                INSERT INTO redaction_decision_links (
                    enforce_plan_id,
                    target_ordinal,
                    preview_plan_id,
                    finding_id,
                    source_block_decision_id,
                    derived_redact_decision_id,
                    derivation_version,
                    metadata_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(_redaction_decision_link_values(link) for link in links),
            )
            stored_row = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_SELECT_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ?
                """,
                (enforce.plan_id,),
            ).fetchone()
            if stored_row is None:
                raise RuntimeError("redaction enforcement insert is missing")
            stored_target_rows = conn.execute(
                f"""
                SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                FROM redaction_targets
                WHERE plan_id = ?
                ORDER BY ordinal
                LIMIT ?
                """,
                (
                    enforce.plan_id,
                    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                ),
            ).fetchall()
            stored_link_rows = conn.execute(
                f"""
                SELECT {_REDACTION_DECISION_LINK_SELECT_COLUMNS}
                FROM redaction_decision_links
                WHERE enforce_plan_id = ?
                ORDER BY target_ordinal
                LIMIT ?
                """,
                (
                    enforce.plan_id,
                    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                ),
            ).fetchall()
            stored = _stored_redaction_plan_from_rows(
                stored_row,
                stored_target_rows,
            )
            stored_links = tuple(
                _stored_redaction_decision_link_from_row(row)
                for row in stored_link_rows
            )
            if not _prepared_redaction_enforcement_matches(
                expected=enforce,
                actual=stored,
                expected_links=links,
                actual_links=stored_links,
            ):
                raise RuntimeError("redaction enforcement insert is incomplete")
            return stored

    def list_redaction_decision_links(
        self,
        enforce_plan_id: str,
        *,
        workspace_id: str,
    ) -> list[StoredRedactionDecisionLink]:
        if self._redaction_audit_available is not True:
            raise RuntimeError("redaction decision linkage schema is unavailable")
        if (
            not isinstance(enforce_plan_id, str)
            or _LOWER_SHA256_RE.fullmatch(enforce_plan_id) is None
            or not _bounded_audit_identifier(workspace_id)
        ):
            raise ValueError(
                "redaction decision link lookup requires bounded ids"
            )
        with self._connect_redaction_audit() as conn:
            rows = conn.execute(
                f"""
                SELECT {_REDACTION_DECISION_LINK_SELECT_COLUMNS}
                FROM redaction_decision_links AS link
                WHERE link.enforce_plan_id = ?
                  AND EXISTS (
                      SELECT 1
                      FROM redaction_plans AS plan
                      WHERE plan.plan_id = link.enforce_plan_id
                        AND plan.workspace_id = ?
                  )
                ORDER BY link.target_ordinal
                LIMIT ?
                """,
                (
                    enforce_plan_id,
                    workspace_id,
                    REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
                ),
            ).fetchall()
        if len(rows) > REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS:
            raise ValueError("redaction decision link limit exceeded")
        return [_stored_redaction_decision_link_from_row(row) for row in rows]

    def confirm_redaction_post_input(
        self,
        post_event: NormalizedEvent,
        *,
        profile_registry: McpProfileRegistry = DEFAULT_MCP_PROFILE_REGISTRY,
    ) -> RedactionPostConfirmationResult:
        """Confirm one future rendered MCP input without enabling rewriting.

        ``record`` must have stored the same PostToolUse event immediately before
        this call. Preview plans are intentionally excluded: only a future
        enforce renderer may create the ``rendered`` state observed here.
        """
        if self._redaction_audit_available is not True:
            return RedactionPostConfirmationResult(
                "not_applicable",
                diagnostic_code="audit_unavailable",
            )
        expected_scope_sha256 = _redaction_call_scope_sha256(post_event)
        if post_event.phase != "post_tool_use" or expected_scope_sha256 is None:
            return RedactionPostConfirmationResult(
                "not_applicable",
                diagnostic_code="unsupported_post_scope",
            )

        with self._connect_redaction_audit() as conn:
            # Current production has no rendered plans. Keep that dormant path
            # read-only and upgrade the same snapshot only for one terminal CAS.
            conn.execute("BEGIN")
            rows = conn.execute(
                """
                SELECT
                    plan.plan_id,
                    plan.analysis_run_id,
                    plan.pre_event_id,
                    plan.adapter,
                    plan.profile_id,
                    plan.profile_version,
                    plan.profile_registry_version,
                    plan.mode,
                    plan.status,
                    plan.planner_version,
                    plan.rewritten_input_sha256,
                    plan.structure_sha256_after,
                    plan.critical_finding_count,
                    plan.replacement_count,
                    plan.rejection_code,
                    plan.post_event_id,
                    plan.rendered_at,
                    plan.confirmed_at,
                    analysis.workspace_id,
                    analysis.session_id,
                    analysis.completed_at
                FROM redaction_plans AS plan
                LEFT JOIN analysis_runs AS analysis
                  ON analysis.analysis_run_id = plan.analysis_run_id
                JOIN event_payload_metadata AS pre_scope
                  ON pre_scope.event_id = plan.pre_event_id
                 AND pre_scope.redaction_event_kind = 'pre'
                 AND pre_scope.redaction_scope_sha256 = ?
                WHERE plan.workspace_id = ?
                  AND plan.session_id = ?
                  AND plan.tool_use_id = ?
                  AND plan.tool_name = ?
                  AND plan.mode = 'enforce'
                  AND plan.status IN (
                      'rendered',
                      'post_confirmed',
                      'post_mismatch'
                  )
                ORDER BY plan.created_at DESC, plan.plan_id
                LIMIT 2
                """,
                (
                    expected_scope_sha256,
                    post_event.workspace_id,
                    post_event.session_id,
                    post_event.tool_use_id,
                    post_event.tool_name,
                ),
            ).fetchall()
            if not rows:
                # A missing/corrupt Pre sidecar must not erase evidence that a
                # rendered plan exists. Scan only the narrow metadata rows for
                # this bounded coarse identity; valid rows for another turn are
                # ignored, while unavailable ownership remains unobserved.
                coarse_rows = conn.execute(
                    f"""
                    SELECT
                        plan.plan_id,
                        {_QUALIFIED_PRE_EVENT_PAYLOAD_METADATA_COLUMNS}
                    FROM redaction_plans AS plan
                    LEFT JOIN event_payload_metadata AS pre_scope
                      ON pre_scope.event_id = plan.pre_event_id
                    WHERE plan.workspace_id = ?
                      AND plan.session_id = ?
                      AND plan.tool_use_id = ?
                      AND plan.tool_name = ?
                      AND plan.mode = 'enforce'
                      AND plan.status IN (
                          'rendered',
                          'post_confirmed',
                          'post_mismatch'
                      )
                    ORDER BY plan.created_at DESC, plan.plan_id
                    LIMIT ?
                    """,
                    (
                        post_event.workspace_id,
                        post_event.session_id,
                        post_event.tool_use_id,
                        post_event.tool_name,
                        REDACTION_CONFIRMATION_MAX_PLAN_CANDIDATES + 1,
                    ),
                ).fetchall()
                if not coarse_rows:
                    return RedactionPostConfirmationResult("not_applicable")
                if (
                    len(coarse_rows)
                    > REDACTION_CONFIRMATION_MAX_PLAN_CANDIDATES
                ):
                    return RedactionPostConfirmationResult(
                        "conflict",
                        diagnostic_code="redaction_candidate_limit_exceeded",
                    )
                unavailable_plan_ids: list[str] = []
                for coarse_row in coarse_rows:
                    pre_scope = _event_payload_metadata_from_row(coarse_row[1:])
                    if (
                        pre_scope is None
                        or pre_scope.redaction_event_kind != "pre"
                    ):
                        unavailable_plan_ids.append(str(coarse_row[0]))
                if unavailable_plan_ids:
                    return RedactionPostConfirmationResult(
                        "unobserved",
                        plan_id=(
                            unavailable_plan_ids[0]
                            if len(unavailable_plan_ids) == 1
                            else None
                        ),
                        diagnostic_code="pre_scope_metadata_unavailable",
                    )
                return RedactionPostConfirmationResult("not_applicable")
            if len(rows) != 1:
                return RedactionPostConfirmationResult(
                    "conflict",
                    diagnostic_code="ambiguous_rendered_plan",
                )

            # Only future rendered plans touch the physically narrow sidecar.
            # Never read the Post events row: upgraded identity columns can sit
            # after an unbounded payload on overflow pages. Legacy rows remain
            # deliberately unavailable instead of being backfilled.
            post_metadata_row = conn.execute(
                f"""
                SELECT {_EVENT_PAYLOAD_METADATA_COLUMNS}
                FROM event_payload_metadata
                WHERE event_id = ?
                """,
                (post_event.event_id,),
            ).fetchone()
            if post_metadata_row is None:
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=rows[0][0],
                    diagnostic_code="post_payload_bytes_unavailable",
                )
            post_metadata = _event_payload_metadata_from_row(
                post_metadata_row
            )
            if post_metadata is None:
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=rows[0][0],
                    diagnostic_code="post_payload_metadata_invalid",
                )
            if (
                post_metadata.event_id != post_event.event_id
                or post_metadata.redaction_event_kind != "post"
                or post_metadata.redaction_scope_sha256
                != expected_scope_sha256
            ):
                raise ValueError(
                    "redaction confirmation PostToolUse metadata identity mismatch"
                )
            post_observation = post_metadata.post_input_observation
            if (
                post_metadata.payload_bytes
                > REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES
            ):
                if (
                    post_observation.status != "unobserved"
                    or post_observation.diagnostic_code
                    != "post_payload_bytes_exceeded"
                ):
                    return RedactionPostConfirmationResult(
                        "unobserved",
                        plan_id=rows[0][0],
                        diagnostic_code="post_payload_metadata_invalid",
                    )
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=rows[0][0],
                    diagnostic_code="post_payload_bytes_exceeded",
                )
            if (
                post_observation.diagnostic_code
                == "post_payload_bytes_exceeded"
            ):
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=rows[0][0],
                    diagnostic_code="post_payload_metadata_invalid",
                )
            post_sequence_no = post_metadata.sequence_no

            (
                plan_id,
                analysis_run_id,
                pre_event_id,
                adapter,
                profile_id,
                profile_version,
                profile_registry_version,
                mode,
                status,
                planner_version,
                rewritten_input_sha256,
                structure_sha256_after,
                critical_finding_count,
                replacement_count,
                rejection_code,
                linked_post_event_id,
                rendered_at,
                confirmed_at,
                analysis_workspace_id,
                analysis_session_id,
                analysis_completed_at,
            ) = rows[0]

            expected_plan_id = hashlib.sha256(
                "\0".join(
                    (
                        post_event.workspace_id,
                        pre_event_id,
                        analysis_run_id,
                        planner_version,
                        profile_version,
                        "enforce",
                    )
                ).encode("utf-8")
            ).hexdigest()
            if (
                plan_id != expected_plan_id
                or adapter != "mcp"
                or mode != "enforce"
                or planner_version != REDACTION_PREVIEW_PLANNER_VERSION
                or not isinstance(rewritten_input_sha256, str)
                or not _LOWER_SHA256_RE.fullmatch(rewritten_input_sha256)
                or not isinstance(structure_sha256_after, str)
                or not _LOWER_SHA256_RE.fullmatch(structure_sha256_after)
                or type(critical_finding_count) is not int
                or critical_finding_count <= 0
                or critical_finding_count
                > REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
                or type(replacement_count) is not int
                or not 0 < replacement_count <= critical_finding_count
                or rejection_code is not None
                or not isinstance(rendered_at, str)
                or not rendered_at
            ):
                raise ValueError("rendered redaction plan integrity mismatch")
            pre_metadata_row = conn.execute(
                f"""
                SELECT {_EVENT_PAYLOAD_METADATA_COLUMNS}
                FROM event_payload_metadata
                WHERE event_id = ?
                """,
                (pre_event_id,),
            ).fetchone()
            pre_metadata = _event_payload_metadata_from_row(pre_metadata_row)
            if (
                pre_metadata is None
                or pre_metadata.redaction_event_kind != "pre"
                or pre_metadata.redaction_scope_sha256
                != expected_scope_sha256
                or pre_metadata.sequence_no >= post_sequence_no
                or analysis_workspace_id != post_event.workspace_id
                or analysis_session_id != post_event.session_id
                or analysis_completed_at is None
            ):
                raise ValueError("redaction confirmation owner mismatch")

            earliest_post_row = conn.execute(
                f"""
                SELECT {_EVENT_PAYLOAD_METADATA_COLUMNS}
                FROM event_payload_metadata
                WHERE redaction_scope_sha256 = ?
                  AND redaction_event_kind = 'post'
                  AND sequence_no > ?
                ORDER BY sequence_no, event_id
                LIMIT 1
                """,
                (
                    expected_scope_sha256,
                    pre_metadata.sequence_no,
                ),
            ).fetchone()
            if earliest_post_row is None:
                raise ValueError("redaction confirmation PostToolUse event is missing")
            earliest_post = _event_payload_metadata_from_row(
                earliest_post_row
            )
            if (
                earliest_post is None
                or earliest_post.redaction_event_kind != "post"
                or earliest_post.redaction_scope_sha256
                != expected_scope_sha256
            ):
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=plan_id,
                    diagnostic_code="post_payload_metadata_invalid",
                )
            if earliest_post.event_id != post_event.event_id:
                return RedactionPostConfirmationResult(
                    "conflict",
                    plan_id=plan_id,
                    diagnostic_code="earlier_post_event_exists",
                )

            enforce_values = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_VALUE_COLUMNS}
                FROM redaction_plans
                WHERE plan_id = ?
                """,
                (plan_id,),
            ).fetchone()
            preview_values = conn.execute(
                f"""
                SELECT {_REDACTION_PLAN_VALUE_COLUMNS}
                FROM redaction_plans
                WHERE workspace_id = ?
                  AND pre_event_id = ?
                  AND analysis_run_id = ?
                  AND planner_version = ?
                  AND profile_version = ?
                  AND mode = 'preview'
                """,
                (
                    post_event.workspace_id,
                    pre_event_id,
                    analysis_run_id,
                    planner_version,
                    profile_version,
                ),
            ).fetchone()
            preview_plan_id = hashlib.sha256(
                "\0".join(
                    (
                        post_event.workspace_id,
                        pre_event_id,
                        analysis_run_id,
                        planner_version,
                        profile_version,
                        "preview",
                    )
                ).encode("utf-8")
            ).hexdigest()
            if enforce_values is None:
                raise ValueError("rendered redaction plan is missing")
            expected_preview_values = list(enforce_values)
            expected_preview_values[0] = preview_plan_id
            expected_preview_values[11] = "preview"
            expected_preview_values[12] = "eligible"
            expected_preview_values[21] = None
            expected_preview_values[22] = None
            expected_preview_values[23] = None
            if preview_values != tuple(expected_preview_values):
                raise ValueError(
                    "rendered redaction plan lacks a verified preview owner"
                )

            target_limit = REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1
            enforce_targets = conn.execute(
                f"""
                SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                FROM redaction_targets
                WHERE plan_id = ?
                ORDER BY ordinal
                LIMIT ?
                """,
                (plan_id, target_limit),
            ).fetchall()
            preview_targets = conn.execute(
                f"""
                SELECT {_REDACTION_TARGET_VALUE_COLUMNS}
                FROM redaction_targets
                WHERE plan_id = ?
                ORDER BY ordinal
                LIMIT ?
                """,
                (preview_plan_id, target_limit),
            ).fetchall()
            decision_link_rows = conn.execute(
                f"""
                SELECT {_REDACTION_DECISION_LINK_SELECT_COLUMNS}
                FROM redaction_decision_links
                WHERE enforce_plan_id = ?
                ORDER BY target_ordinal
                LIMIT ?
                """,
                (plan_id, target_limit),
            ).fetchall()
            _validate_redaction_confirmation_decision_links(
                enforce_plan_id=plan_id,
                preview_plan_id=preview_plan_id,
                analysis_run_id=analysis_run_id,
                critical_finding_count=critical_finding_count,
                enforce_target_rows=enforce_targets,
                preview_target_rows=preview_targets,
                decision_link_rows=decision_link_rows,
            )

            if status in {"post_confirmed", "post_mismatch"}:
                if (
                    linked_post_event_id is None
                    or (status == "post_confirmed") != (confirmed_at is not None)
                ):
                    raise ValueError(
                        "redaction confirmation terminal state is invalid"
                    )
                if linked_post_event_id == post_event.event_id:
                    return RedactionPostConfirmationResult(
                        (
                            "confirmed"
                            if status == "post_confirmed"
                            else "mismatch"
                        ),
                        plan_id=plan_id,
                        replayed=True,
                    )
                return RedactionPostConfirmationResult(
                    "conflict",
                    plan_id=plan_id,
                    diagnostic_code="post_observation_already_recorded",
                )
            if (
                status != "rendered"
                or linked_post_event_id is not None
                or confirmed_at is not None
            ):
                raise ValueError("rendered redaction plan state is invalid")

            comparison = compare_mcp_post_observation(
                tool_name=post_event.tool_name,
                observation=post_observation,
                profile_id=profile_id,
                profile_version=profile_version,
                profile_registry_version=profile_registry_version,
                rewritten_input_sha256=rewritten_input_sha256,
                structure_sha256_after=structure_sha256_after,
                profile_registry=profile_registry,
            )
            if comparison.disposition == "unobserved":
                return RedactionPostConfirmationResult(
                    "unobserved",
                    plan_id=plan_id,
                    diagnostic_code=comparison.diagnostic_code,
                )

            next_status = (
                "post_confirmed"
                if comparison.disposition == "confirmed"
                else "post_mismatch"
            )
            updated = conn.execute(
                """
                UPDATE redaction_plans
                SET
                    status = ?,
                    post_event_id = ?,
                    confirmed_at = CASE
                        WHEN ? = 'post_confirmed' THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END
                WHERE plan_id = ?
                  AND mode = 'enforce'
                  AND status = 'rendered'
                  AND rendered_at IS NOT NULL
                  AND post_event_id IS NULL
                  AND confirmed_at IS NULL
                """,
                (
                    next_status,
                    post_event.event_id,
                    next_status,
                    plan_id,
                ),
            ).rowcount
            if updated != 1:
                raise RuntimeError("redaction confirmation state changed")
            return RedactionPostConfirmationResult(
                comparison.disposition,
                plan_id=plan_id,
            )

    def cleanup_redaction_audits(
        self,
        *,
        workspace_id: str,
        before: str,
        session_id: str | None = None,
        execute: bool = False,
    ) -> RedactionAuditCleanupResult:
        """Count or delete preview audits using their owning event retention scope."""
        if not workspace_id:
            raise ValueError("redaction cleanup requires a workspace id")
        if session_id is not None and not session_id:
            raise ValueError("redaction cleanup session must not be empty")
        if type(execute) is not bool:
            raise ValueError("redaction cleanup execute flag must be boolean")
        _validate_sqlite_utc_timestamp(before)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TEMP TABLE redaction_cleanup_candidates (
                    plan_id TEXT PRIMARY KEY,
                    is_orphan INTEGER NOT NULL
                )
                """
            )
            conn.execute("BEGIN IMMEDIATE" if execute else "BEGIN")
            self._validate_registered_workspace(conn, workspace_id)
            filters = ["plan.workspace_id = ?"]
            params: list[object] = [workspace_id]
            if session_id is not None:
                filters.append("plan.session_id = ?")
                params.append(session_id)

            corrupt = conn.execute(
                f"""
                SELECT 1
                FROM redaction_plans AS plan
                JOIN events AS event ON event.event_id = plan.pre_event_id
                WHERE {' AND '.join(filters)}
                  AND (
                      event.phase != 'pre_tool_use'
                      OR event.workspace_status != 'ready'
                      OR event.workspace_id IS NOT plan.workspace_id
                      OR event.session_id IS NOT plan.session_id
                      OR event.tool_use_id IS NOT plan.tool_use_id
                      OR event.tool_name IS NOT plan.tool_name
                  )
                LIMIT 1
                """,
                params,
            ).fetchone()
            if corrupt is not None:
                raise ValueError("redaction cleanup found an invalid event owner")

            conn.execute(
                f"""
                INSERT INTO redaction_cleanup_candidates (plan_id, is_orphan)
                SELECT
                    plan.plan_id,
                    CASE WHEN event.event_id IS NULL THEN 1 ELSE 0 END
                FROM redaction_plans AS plan
                LEFT JOIN events AS event ON event.event_id = plan.pre_event_id
                WHERE {' AND '.join(filters)}
                  AND (
                      event.event_id IS NULL
                      OR event.recorded_at < ?
                  )
                """,
                (*params, before),
            )
            plan_count, orphan_plan_count = conn.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(is_orphan), 0)
                FROM redaction_cleanup_candidates
                """
            ).fetchone()
            target_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM redaction_targets AS target
                JOIN redaction_cleanup_candidates AS candidate
                  ON candidate.plan_id = target.plan_id
                """
            ).fetchone()[0]
            decision_link_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM redaction_decision_links AS link
                WHERE link.enforce_plan_id IN (
                    SELECT plan_id FROM redaction_cleanup_candidates
                )
                   OR link.preview_plan_id IN (
                    SELECT plan_id FROM redaction_cleanup_candidates
                )
                """
            ).fetchone()[0]
            if execute:
                deleted_decision_links = conn.execute(
                    """
                    DELETE FROM redaction_decision_links
                    WHERE enforce_plan_id IN (
                        SELECT plan_id FROM redaction_cleanup_candidates
                    )
                       OR preview_plan_id IN (
                        SELECT plan_id FROM redaction_cleanup_candidates
                    )
                    """
                ).rowcount
                deleted_targets = conn.execute(
                    """
                    DELETE FROM redaction_targets
                    WHERE plan_id IN (
                        SELECT plan_id FROM redaction_cleanup_candidates
                    )
                    """
                ).rowcount
                deleted_plans = conn.execute(
                    """
                    DELETE FROM redaction_plans
                    WHERE plan_id IN (
                        SELECT plan_id FROM redaction_cleanup_candidates
                    )
                    """
                ).rowcount
                if (
                    deleted_decision_links != decision_link_count
                    or deleted_targets != target_count
                    or deleted_plans != plan_count
                ):
                    raise RuntimeError("redaction cleanup delete count changed")
        return RedactionAuditCleanupResult(
            workspace_id=workspace_id,
            before=before,
            session_id=session_id,
            plan_count=int(plan_count),
            target_count=int(target_count),
            decision_link_count=int(decision_link_count),
            orphan_plan_count=int(orphan_plan_count),
            executed=execute,
        )

    def _validate_redaction_plan_owner(
        self,
        conn: sqlite3.Connection,
        plan: StoredRedactionPlan,
    ) -> tuple[int, NormalizedEvent, AnalysisRun]:
        self._validate_registered_workspace(conn, plan.workspace_id)
        event = conn.execute(
            """
            SELECT
                phase,
                session_id,
                turn_id,
                tool_use_id,
                tool_name,
                cwd,
                model,
                permission_mode,
                transcript_path,
                stop_hook_active,
                workspace_id,
                workspace_root,
                workspace_lexical_root,
                workspace_execution_cwd,
                workspace_status,
                workspace_source,
                workspace_namespace_id,
                sequence_no,
                payload_json,
                length(CAST(payload_json AS BLOB))
            FROM events
            WHERE event_id = ?
            """,
            (plan.pre_event_id,),
        ).fetchone()
        if (
            event is None
            or (
                event[0],
                event[14],
                event[10],
                event[1],
                event[3],
                event[4],
            )
            != (
                "pre_tool_use",
                "ready",
                plan.workspace_id,
                plan.session_id,
                plan.tool_use_id,
                plan.tool_name,
            )
            or event[17] is None
        ):
            raise ValueError("redaction plan does not match its PreToolUse event")
        if (
            event[19] is None
            or int(event[19]) > REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES
        ):
            raise ValueError("redaction plan event payload limit exceeded")
        try:
            payload = json.loads(event[18])
        except (TypeError, ValueError) as exc:
            raise ValueError("redaction plan event payload is invalid") from exc
        if not isinstance(payload, dict):
            raise ValueError("redaction plan event payload is invalid")
        analysis_row = conn.execute(
            """
            SELECT
                analysis_run_id,
                detector_version,
                config_json,
                started_at,
                completed_at,
                workspace_id,
                session_id
            FROM analysis_runs
            WHERE analysis_run_id = ?
            """,
            (plan.analysis_run_id,),
        ).fetchone()
        if (
            analysis_row is None
            or analysis_row[4] is None
            or analysis_row[5:] != (plan.workspace_id, plan.session_id)
        ):
            raise ValueError(
                "redaction plan requires a completed runtime analysis run"
            )
        normalized_event = NormalizedEvent(
            event_id=plan.pre_event_id,
            phase=event[0],
            session_id=event[1],
            turn_id=event[2],
            tool_use_id=event[3],
            tool_name=event[4],
            cwd=event[5],
            model=event[6],
            permission_mode=event[7],
            transcript_path=event[8],
            stop_hook_active=(None if event[9] is None else bool(event[9])),
            workspace_id=event[10],
            workspace_root=event[11],
            workspace_lexical_root=event[12],
            workspace_execution_cwd=event[13],
            workspace_status=event[14],
            workspace_source=event[15] or "unknown",
            workspace_namespace_id=event[16],
            raw_payload=payload,
        )
        analysis_run = AnalysisRun(*analysis_row)
        return int(event[17]), normalized_event, analysis_run

    def _validate_redaction_plan_replay(
        self,
        conn: sqlite3.Connection,
        plan: StoredRedactionPlan,
        event_sequence_no: int,
        event: NormalizedEvent,
        analysis_run: AnalysisRun,
    ) -> None:
        sink_size_rows = conn.execute(
            """
            SELECT
                length(CAST(node_id AS BLOB)),
                length(CAST(sink_type AS BLOB)),
                length(CAST(label AS BLOB)),
                length(CAST(tool_name AS BLOB)),
                length(CAST(metadata_json AS BLOB))
            FROM sink_candidates
            WHERE workspace_id = ?
              AND session_id = ?
              AND tool_use_id = ?
              AND tool_name = ?
              AND sequence_no = ?
              AND sink_type LIKE 'external_%'
            ORDER BY node_id
            LIMIT ?
            """,
            (
                plan.workspace_id,
                plan.session_id,
                plan.tool_use_id,
                plan.tool_name,
                event_sequence_no,
                REDACTION_AUDIT_MAX_CURRENT_SINKS + 1,
            ),
        ).fetchall()
        if len(sink_size_rows) > REDACTION_AUDIT_MAX_CURRENT_SINKS:
            raise ValueError("redaction audit current sink limit exceeded")
        if any(
            any(size is None for size in row)
            or any(
                int(size) > REDACTION_AUDIT_MAX_IDENTIFIER_BYTES
                for size in row[:4]
            )
            or int(row[4]) > REDACTION_AUDIT_MAX_SINK_METADATA_BYTES
            for row in sink_size_rows
        ):
            raise ValueError("redaction audit sink row byte limit exceeded")
        if (
            sum(int(size) for row in sink_size_rows for size in row)
            > REDACTION_AUDIT_MAX_SINK_BYTES_TOTAL
        ):
            raise ValueError("redaction audit sink total byte limit exceeded")

        sink_rows = conn.execute(
            """
            SELECT
                node_id,
                sink_type,
                label,
                tool_name,
                tool_use_id,
                session_id,
                sequence_no,
                metadata_json,
                workspace_id
            FROM sink_candidates
            WHERE workspace_id = ?
              AND session_id = ?
              AND tool_use_id = ?
              AND tool_name = ?
              AND sequence_no = ?
              AND sink_type LIKE 'external_%'
            ORDER BY node_id
            LIMIT ?
            """,
            (
                plan.workspace_id,
                plan.session_id,
                plan.tool_use_id,
                plan.tool_name,
                event_sequence_no,
                REDACTION_AUDIT_MAX_CURRENT_SINKS + 1,
            ),
        ).fetchall()
        current_sinks: list[SinkCandidate] = []
        for row in sink_rows:
            try:
                metadata = json.loads(row[7])
            except (TypeError, ValueError) as exc:
                raise ValueError("redaction audit sink metadata is invalid") from exc
            if (
                not isinstance(metadata, dict)
                or metadata.get("event_id") != plan.pre_event_id
                or metadata.get("adapter") != plan.adapter
            ):
                continue
            current_sinks.append(
                SinkCandidate(
                    node_id=row[0],
                    sink_type=row[1],
                    label=row[2],
                    tool_name=row[3],
                    tool_use_id=row[4],
                    session_id=row[5],
                    sequence_no=row[6],
                    metadata=metadata,
                    workspace_id=row[8],
                )
            )
        if not current_sinks:
            raise ValueError("redaction audit has no current external sinks")

        sink_ids = tuple(sorted(sink.node_id for sink in current_sinks))
        sink_placeholders = ",".join("?" for _ in sink_ids)
        assignment_rows = conn.execute(
            f"""
            SELECT
                analysis_run_id,
                source_node_kind,
                source_node_id,
                node_kind,
                node_id,
                best_path_score,
                predecessor_edge_id,
                hop_count
            FROM lineage_assignments
            WHERE analysis_run_id = ?
              AND node_kind = 'sink_candidate'
              AND node_id IN ({sink_placeholders})
              AND best_path_score >= 0.9
            ORDER BY source_node_kind, source_node_id, node_id
            LIMIT ?
            """,
            (
                plan.analysis_run_id,
                *sink_ids,
                REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS + 1,
            ),
        ).fetchall()
        if len(assignment_rows) > REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS:
            raise ValueError("redaction audit critical finding limit exceeded")
        assignments = [LineageAssignment(*row) for row in assignment_rows]
        findings = detect_leaks(
            analysis_run=analysis_run,
            assignments=assignments,
            sink_candidates=current_sinks,
            min_score=0.9,
            sink_types={sink.sink_type for sink in current_sinks},
        )
        if len(findings) != plan.critical_finding_count:
            raise ValueError("redaction plan critical findings are incomplete")

        source_ids = tuple(
            sorted(
                {
                    finding.source_node_id
                    for finding in findings
                    if finding.source_node_kind == "source_chunk"
                }
            )
        )
        sources = _load_bounded_source_chunk_evidence(
            conn,
            plan.workspace_id,
            source_ids,
            max_ids=REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS,
            max_bytes_per_chunk=(
                REDACTION_PREVIEW_MAX_SOURCE_BYTES_PER_FINDING
            ),
            max_bytes_total=REDACTION_PREVIEW_MAX_SOURCE_BYTES_TOTAL,
        )
        source_map = {
            (source.workspace_id, source.chunk_id): source for source in sources
        }

        # Import lazily so the storage module does not own policy initialization.
        from hook_monitor.policy.redaction_preview import (
            plan_mcp_redaction_preview,
        )

        replay = plan_mcp_redaction_preview(
            current_event=event,
            current_sequence_no=event_sequence_no,
            analysis_run=analysis_run,
            current_sinks=tuple(current_sinks),
            current_critical_findings=tuple(findings),
            source_chunks=source_map,
            monotonic_ns=lambda: 0,
        )
        if replay.plan is None or not _redaction_preview_matches_stored(
            replay.plan,
            plan,
        ):
            raise ValueError("redaction plan does not match deterministic replay")

    def replace_information_flow_edges(
        self,
        edges: list[FlowEdge],
        *,
        workspace_id: str | None = None,
    ) -> None:
        stored_workspace_id = _stored_derived_workspace_id(workspace_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for table in (
                "information_flow_edge_scopes",
                "analysis_cursors",
                "runtime_lineage_state",
                "runtime_source_binding_edges",
                "information_flow_edges",
            ):
                conn.execute(
                    f"DELETE FROM {table} WHERE workspace_id = ?",
                    (stored_workspace_id,),
                )
            conn.executemany(
                """
                INSERT INTO information_flow_edges (
                    workspace_id,
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, edge_id) DO UPDATE SET
                    src_node_kind = excluded.src_node_kind,
                    src_node_id = excluded.src_node_id,
                    dst_node_kind = excluded.dst_node_kind,
                    dst_node_id = excluded.dst_node_id,
                    relation = excluded.relation,
                    evidence_level = excluded.evidence_level,
                    method = excluded.method,
                    score = excluded.score,
                    reason = excluded.reason
                """,
                [
                    (
                        stored_workspace_id,
                        edge.edge_id,
                        edge.src_node_kind,
                        edge.src_node_id,
                        edge.dst_node_kind,
                        edge.dst_node_id,
                        edge.relation,
                        edge.evidence_level,
                        edge.method,
                        edge.score,
                        edge.reason,
                    )
                    for edge in edges
                ],
            )

    def replace_information_flow_edges_for_workspace(
        self,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._replace_information_flow_edges_for_workspace(
                conn,
                workspace_id,
                edges,
            )

    def _replace_information_flow_edges_for_workspace(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> None:
        self._validate_registered_workspace(conn, workspace_id)
        self._reject_cross_workspace_flow_edge_collisions(
            conn,
            workspace_id,
            edges,
        )
        self._validate_analysis_run_graph_node_owners(
            conn,
            workspace_id,
            edges,
        )
        for table in (
            "information_flow_edge_scopes",
            "analysis_cursors",
            "runtime_lineage_state",
            "runtime_source_binding_edges",
            "information_flow_edges",
        ):
            conn.execute(
                f"DELETE FROM {table} WHERE workspace_id = ?",
                (workspace_id,),
            )
        conn.executemany(
            """
            INSERT INTO information_flow_edges (
                workspace_id,
                edge_id,
                src_node_kind,
                src_node_id,
                dst_node_kind,
                dst_node_id,
                relation,
                evidence_level,
                method,
                score,
                reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, edge_id) DO UPDATE SET
                src_node_kind = excluded.src_node_kind,
                src_node_id = excluded.src_node_id,
                dst_node_kind = excluded.dst_node_kind,
                dst_node_id = excluded.dst_node_id,
                relation = excluded.relation,
                evidence_level = excluded.evidence_level,
                method = excluded.method,
                score = excluded.score,
                reason = excluded.reason
            """,
            [(workspace_id, *_flow_edge_values(edge)) for edge in edges],
        )

    def upsert_information_flow_edges_for_session(
        self,
        session_id: str,
        sequence_no: int,
        edges: list[FlowEdge],
        *,
        workspace_id: str,
    ) -> None:
        if not edges:
            return
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            self._reject_flow_edge_scope_collisions(
                conn,
                workspace_id,
                session_id,
                edges,
            )
            conn.executemany(
                """
                INSERT INTO information_flow_edges (
                    workspace_id, edge_id, src_node_kind, src_node_id,
                    dst_node_kind, dst_node_id,
                    relation, evidence_level, method, score, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, edge_id) DO UPDATE SET
                    src_node_kind = excluded.src_node_kind,
                    src_node_id = excluded.src_node_id,
                    dst_node_kind = excluded.dst_node_kind,
                    dst_node_id = excluded.dst_node_id,
                    relation = excluded.relation,
                    evidence_level = excluded.evidence_level,
                    method = excluded.method,
                    score = excluded.score,
                    reason = excluded.reason
                """,
                [
                    (workspace_id, *_flow_edge_values(edge))
                    for edge in edges
                ],
            )
            conn.executemany(
                """
                INSERT INTO information_flow_edge_scopes (
                    workspace_id, session_id, edge_id, sequence_no
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, session_id, edge_id) DO UPDATE SET
                    sequence_no = MIN(
                        information_flow_edge_scopes.sequence_no,
                        excluded.sequence_no
                    )
                """,
                [
                    (
                        workspace_id,
                        session_id,
                        edge.edge_id,
                        sequence_no,
                    )
                    for edge in edges
                ],
            )

    def _reject_flow_edge_scope_collisions(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        session_id: str,
        edges: list[FlowEdge],
    ) -> None:
        batch: dict[str, tuple[object, ...]] = {}
        for edge in edges:
            values = _flow_edge_values(edge)[1:]
            previous = batch.get(edge.edge_id)
            if previous is not None and previous != values:
                raise ValueError("flow edge id has conflicting batch payloads")
            batch[edge.edge_id] = values

        edge_ids = sorted(batch)
        for start in range(0, len(edge_ids), 400):
            current_ids = edge_ids[start:start + 400]
            placeholders = ",".join("?" for _ in current_ids)
            rows = conn.execute(
                f"""
                SELECT
                    edge_id,
                    workspace_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                FROM information_flow_edges
                WHERE edge_id IN ({placeholders})
                """,
                current_ids,
            ).fetchall()
            for row in rows:
                edge_id = row[0]
                if row[1] != workspace_id:
                    raise ValueError("flow edge id belongs to another workspace")
                if tuple(row[2:]) != batch[edge_id]:
                    raise ValueError("flow edge id has a conflicting stored payload")
            other_session = conn.execute(
                f"""
                SELECT 1
                FROM information_flow_edge_scopes
                WHERE workspace_id = ?
                  AND edge_id IN ({placeholders})
                  AND session_id != ?
                LIMIT 1
                """,
                (workspace_id, *current_ids, session_id),
            ).fetchone()
            if other_session is not None:
                raise ValueError("flow edge id belongs to another session")

    def _reject_cross_workspace_flow_edge_collisions(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        edges: list[FlowEdge],
    ) -> None:
        batch: dict[str, tuple[object, ...]] = {}
        for edge in edges:
            values = _flow_edge_values(edge)[1:]
            previous = batch.get(edge.edge_id)
            if previous is not None and previous != values:
                raise ValueError("flow edge id has conflicting batch payloads")
            batch[edge.edge_id] = values
        edge_ids = sorted(batch)
        for start in range(0, len(edge_ids), 400):
            current_ids = edge_ids[start:start + 400]
            placeholders = ",".join("?" for _ in current_ids)
            collision = conn.execute(
                f"""
                SELECT 1
                FROM information_flow_edges
                WHERE edge_id IN ({placeholders})
                  AND workspace_id != ?
                LIMIT 1
                """,
                (*current_ids, workspace_id),
            ).fetchone()
            if collision is not None:
                raise ValueError("flow edge id belongs to another workspace")

    def replace_resource_versions(
        self,
        resources: list[ResourceVersion],
        *,
        workspace_id: str | None = None,
    ) -> None:
        owners = {resource.workspace_id for resource in resources}
        if workspace_id is None and owners and owners != {None}:
            if len(owners) != 1:
                raise ValueError("resource versions span multiple workspaces")
            workspace_id = next(iter(owners))
        if any(resource.workspace_id != workspace_id for resource in resources):
            raise ValueError("resource version workspace does not match replace scope")
        stored_workspace_id = _stored_derived_workspace_id(workspace_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM resource_versions WHERE workspace_id = ?",
                (stored_workspace_id,),
            )
            conn.executemany(
                """
                INSERT INTO resource_versions (
                    node_id,
                    workspace_id,
                    path,
                    content_hash,
                    sequence_no,
                    session_id,
                    origin_tool_use_id,
                    operation_id,
                    operation_index,
                    snapshot_id,
                    resource_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        resource.node_id,
                        stored_workspace_id,
                        resource.path,
                        resource.content_hash,
                        resource.sequence_no,
                        resource.session_id,
                        resource.origin_tool_use_id,
                        resource.operation_id,
                        resource.operation_index,
                        resource.snapshot_id,
                        resource.resource_state,
                    )
                    for resource in resources
                ],
            )

    def replace_resource_versions_for_workspace(
        self,
        workspace_id: str,
        resources: list[ResourceVersion],
    ) -> None:
        if any(resource.workspace_id != workspace_id for resource in resources):
            raise ValueError("resource version workspace does not match replace scope")
        nodes = [
            (resource.node_id, resource.workspace_id)
            for resource in resources
        ]
        _validate_node_workspace_owners(nodes)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._replace_resource_versions_for_workspace(
                conn,
                workspace_id,
                resources,
            )

    def _replace_resource_versions_for_workspace(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        resources: list[ResourceVersion],
    ) -> None:
        self._validate_registered_workspace(conn, workspace_id)
        self._reject_cross_workspace_node_collisions(
            conn,
            "resource_versions",
            [(resource.node_id, workspace_id) for resource in resources],
        )
        conn.execute(
            "DELETE FROM resource_versions WHERE workspace_id = ?",
            (workspace_id,),
        )
        conn.executemany(
            """
            INSERT INTO resource_versions (
                node_id,
                workspace_id,
                path,
                content_hash,
                sequence_no,
                session_id,
                origin_tool_use_id,
                operation_id,
                operation_index,
                snapshot_id,
                resource_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [_resource_values(resource) for resource in resources],
        )

    def upsert_resource_versions(
        self,
        resources: list[ResourceVersion],
        *,
        workspace_id: str,
        session_id: str,
    ) -> None:
        if not resources:
            return
        if any(
            resource.workspace_id != workspace_id
            or resource.session_id != session_id
            for resource in resources
        ):
            raise ValueError("resource version workspace does not match write scope")
        nodes = [
            (
                resource.node_id,
                workspace_id,
            )
            for resource in resources
        ]
        _validate_node_workspace_owners(nodes)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            self._reject_cross_workspace_node_collisions(
                conn,
                "resource_versions",
                nodes,
            )
            self._reject_cross_session_node_collisions(
                conn,
                "resource_versions",
                nodes,
                session_id,
            )
            conn.executemany(
                """
                INSERT INTO resource_versions (
                    node_id, workspace_id, path, content_hash, sequence_no, session_id,
                    origin_tool_use_id, operation_id, operation_index,
                    snapshot_id, resource_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, node_id) DO UPDATE SET
                    path = excluded.path,
                    content_hash = excluded.content_hash,
                    sequence_no = excluded.sequence_no,
                    session_id = excluded.session_id,
                    origin_tool_use_id = excluded.origin_tool_use_id,
                    operation_id = excluded.operation_id,
                    operation_index = excluded.operation_index,
                    snapshot_id = excluded.snapshot_id,
                    resource_state = excluded.resource_state
                """,
                [_resource_values(resource) for resource in resources],
            )

    def replace_sink_candidates(
        self,
        sinks: list[SinkCandidate],
        *,
        workspace_id: str | None = None,
    ) -> None:
        owners = {sink.workspace_id for sink in sinks}
        if workspace_id is None and owners and owners != {None}:
            if len(owners) != 1:
                raise ValueError("sink candidates span multiple workspaces")
            workspace_id = next(iter(owners))
        if any(sink.workspace_id != workspace_id for sink in sinks):
            raise ValueError("sink candidate workspace does not match replace scope")
        stored_workspace_id = _stored_derived_workspace_id(workspace_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM sink_candidates WHERE workspace_id = ?",
                (stored_workspace_id,),
            )
            conn.executemany(
                """
                INSERT INTO sink_candidates (
                    node_id,
                    workspace_id,
                    sink_type,
                    label,
                    tool_name,
                    tool_use_id,
                    session_id,
                    sequence_no,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        sink.node_id,
                        stored_workspace_id,
                        sink.sink_type,
                        sink.label,
                        sink.tool_name,
                        sink.tool_use_id,
                        sink.session_id,
                        sink.sequence_no,
                        json.dumps(sink.metadata, ensure_ascii=False, sort_keys=True),
                    )
                    for sink in sinks
                ],
            )

    def replace_sink_candidates_for_workspace(
        self,
        workspace_id: str,
        sinks: list[SinkCandidate],
    ) -> None:
        if any(sink.workspace_id != workspace_id for sink in sinks):
            raise ValueError("sink candidate workspace does not match replace scope")
        nodes = [
            (sink.node_id, sink.workspace_id)
            for sink in sinks
        ]
        _validate_node_workspace_owners(nodes)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._replace_sink_candidates_for_workspace(
                conn,
                workspace_id,
                sinks,
            )

    def _replace_sink_candidates_for_workspace(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        sinks: list[SinkCandidate],
    ) -> None:
        self._validate_registered_workspace(conn, workspace_id)
        self._reject_cross_workspace_node_collisions(
            conn,
            "sink_candidates",
            [(sink.node_id, workspace_id) for sink in sinks],
        )
        conn.execute(
            "DELETE FROM sink_candidates WHERE workspace_id = ?",
            (workspace_id,),
        )
        conn.executemany(
            """
            INSERT INTO sink_candidates (
                node_id,
                workspace_id,
                sink_type,
                label,
                tool_name,
                tool_use_id,
                session_id,
                sequence_no,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [_sink_values(sink) for sink in sinks],
        )

    def upsert_sink_candidates(
        self,
        sinks: list[SinkCandidate],
        *,
        workspace_id: str,
        session_id: str,
    ) -> None:
        if not sinks:
            return
        if any(
            sink.workspace_id != workspace_id or sink.session_id != session_id
            for sink in sinks
        ):
            raise ValueError("sink candidate workspace does not match write scope")
        nodes = [
            (sink.node_id, workspace_id)
            for sink in sinks
        ]
        _validate_node_workspace_owners(nodes)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            self._reject_cross_workspace_node_collisions(
                conn,
                "sink_candidates",
                nodes,
            )
            self._reject_cross_session_node_collisions(
                conn,
                "sink_candidates",
                nodes,
                session_id,
            )
            conn.executemany(
                """
                INSERT INTO sink_candidates (
                    node_id, workspace_id, sink_type, label, tool_name, tool_use_id, session_id,
                    sequence_no, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, node_id) DO UPDATE SET
                    sink_type = excluded.sink_type,
                    label = excluded.label,
                    tool_name = excluded.tool_name,
                    tool_use_id = excluded.tool_use_id,
                    session_id = excluded.session_id,
                    sequence_no = excluded.sequence_no,
                    metadata_json = excluded.metadata_json
                """,
                [_sink_values(sink) for sink in sinks],
            )

    def _reject_cross_workspace_node_collisions(
        self,
        conn: sqlite3.Connection,
        table: str,
        nodes: list[tuple[str, str]],
    ) -> None:
        for node_id, workspace_id in nodes:
            row = conn.execute(
                f"""
                SELECT 1 FROM {table}
                WHERE node_id = ? AND workspace_id != ?
                LIMIT 1
                """,
                (node_id, workspace_id),
            ).fetchone()
            if row is not None:
                raise ValueError("derived node id belongs to another workspace")

    def _reject_cross_session_node_collisions(
        self,
        conn: sqlite3.Connection,
        table: str,
        nodes: list[tuple[str, str]],
        session_id: str,
    ) -> None:
        for node_id, workspace_id in nodes:
            row = conn.execute(
                f"""
                SELECT 1 FROM {table}
                WHERE workspace_id = ?
                  AND node_id = ?
                  AND session_id IS NOT ?
                LIMIT 1
                """,
                (workspace_id, node_id, session_id),
            ).fetchone()
            if row is not None:
                raise ValueError("derived node id belongs to another session")

    def _validate_runtime_scope_owner(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        session_id: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT 1
            FROM workspaces AS w
            WHERE w.workspace_id = ?
              AND EXISTS (
                  SELECT 1
                  FROM events AS e
                  WHERE e.workspace_id = w.workspace_id
                    AND e.workspace_status = 'ready'
                    AND e.session_id = ?
              )
            """,
            (workspace_id, session_id),
        ).fetchone()
        if row is None:
            raise ValueError("runtime analysis scope is not registered")

    def _validate_registered_workspace(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT canonical_root
            FROM workspaces
            WHERE workspace_id = ?
            """,
            (workspace_id,),
        ).fetchone()
        if (
            row is None
            or not row[0]
            or make_workspace_id(row[0]) != workspace_id
        ):
            raise ValueError("workspace analysis requires a registered workspace")

    def _validate_runtime_analysis_run_owner(
        self,
        conn: sqlite3.Connection,
        analysis_run_id: str,
        workspace_id: str,
        session_id: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT workspace_id, session_id
            FROM analysis_runs
            WHERE analysis_run_id = ?
            """,
            (analysis_run_id,),
        ).fetchone()
        if row != (workspace_id, session_id):
            raise ValueError("analysis run does not match runtime scope")

    def _validate_mutable_analysis_run(
        self,
        conn: sqlite3.Connection,
        analysis_run_id: str,
    ) -> tuple[str | None, str | None]:
        row = conn.execute(
            """
            SELECT workspace_id, session_id, completed_at
            FROM analysis_runs
            WHERE analysis_run_id = ?
            """,
            (analysis_run_id,),
        ).fetchone()
        if row is None:
            raise ValueError("analysis run does not exist")
        if row[2] is not None:
            raise ValueError("completed analysis run is immutable")
        workspace_id = row[0]
        session_id = row[1]
        if workspace_id is not None:
            self._validate_registered_workspace(conn, workspace_id)
        return workspace_id, session_id

    def upsert_source_binding_edges(
        self,
        analysis_run_id: str,
        edges: list[FlowEdge],
        *,
        _connection: sqlite3.Connection | None = None,
    ) -> None:
        batch: dict[str, tuple[object, ...]] = {}
        for edge in edges:
            if not isinstance(edge.edge_id, str) or not edge.edge_id:
                raise ValueError("source binding edge id is invalid")
            values = _flow_edge_values(edge)[1:]
            previous = batch.get(edge.edge_id)
            if previous is not None and previous != values:
                raise ValueError("source binding edge has conflicting batch payloads")
            batch[edge.edge_id] = values
        owns_connection = _connection is None
        connection_context = (
            self._connect() if owns_connection else nullcontext(_connection)
        )
        with connection_context as conn:
            if owns_connection:
                conn.execute("BEGIN IMMEDIATE")
            workspace_id, session_id = self._validate_mutable_analysis_run(
                conn,
                analysis_run_id,
            )
            if workspace_id is not None:
                self._validate_analysis_run_graph_node_owners(
                    conn,
                    workspace_id,
                    edges,
                )
            if workspace_id is not None and session_id is None and batch:
                edge_ids = sorted(batch)
                for start in range(0, len(edge_ids), 300):
                    current_ids = edge_ids[start:start + 300]
                    placeholders = ",".join("?" for _ in current_ids)
                    rows = conn.execute(
                        f"""
                        SELECT edge_id, src_node_kind, src_node_id,
                               dst_node_kind, dst_node_id, relation,
                               evidence_level, method, score, reason
                        FROM analysis_run_flow_edges
                        WHERE analysis_run_id = ?
                          AND edge_id IN ({placeholders})
                        """,
                        (analysis_run_id, *current_ids),
                    ).fetchall()
                    found = {row[0]: tuple(row[1:]) for row in rows}
                    if set(found) != set(current_ids) or any(
                        found[edge_id] != batch[edge_id]
                        for edge_id in current_ids
                    ):
                        raise ValueError(
                            "source binding edge is not in the immutable run graph"
                        )
            conn.executemany(
                """
                INSERT OR REPLACE INTO source_binding_edges (
                    analysis_run_id,
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (analysis_run_id, edge_id, *values)
                    for edge_id, values in sorted(batch.items())
                ],
            )

    def list_information_flow_edges(self) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                FROM information_flow_edges
                """
            ).fetchall()
        return [
            FlowEdge(
                edge_id=row[0],
                src_node_kind=row[1],
                src_node_id=row[2],
                dst_node_kind=row[3],
                dst_node_id=row[4],
                relation=row[5],
                evidence_level=row[6],
                method=row[7],
                score=row[8],
                reason=row[9],
            )
            for row in rows
        ]

    def list_information_flow_edges_for_workspace(
        self,
        workspace_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                FROM information_flow_edges
                WHERE workspace_id = ?
                ORDER BY edge_id
                """,
                (workspace_id,),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def list_information_flow_edges_for_session(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    e.edge_id, e.src_node_kind, e.src_node_id, e.dst_node_kind,
                    e.dst_node_id, e.relation, e.evidence_level, e.method,
                    e.score, e.reason
                FROM information_flow_edges AS e
                JOIN information_flow_edge_scopes AS s
                  ON s.workspace_id = e.workspace_id
                 AND s.edge_id = e.edge_id
                WHERE s.workspace_id = ? AND s.session_id = ?
                """,
                (workspace_id, session_id),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def clear_runtime_analysis_for_session(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            edge_ids = [
                row[0]
                for row in conn.execute(
                    """
                    SELECT edge_id FROM information_flow_edge_scopes
                    WHERE workspace_id = ? AND session_id = ?
                    """,
                    (workspace_id, session_id),
                ).fetchall()
            ]
            conn.execute(
                """
                DELETE FROM information_flow_edge_scopes
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            if edge_ids:
                placeholders = ",".join("?" for _ in edge_ids)
                conn.execute(
                    f"""
                    DELETE FROM information_flow_edges
                    WHERE workspace_id = ?
                      AND edge_id IN ({placeholders})
                      AND NOT EXISTS (
                          SELECT 1 FROM information_flow_edge_scopes AS scope
                          WHERE scope.workspace_id = information_flow_edges.workspace_id
                            AND scope.edge_id = information_flow_edges.edge_id
                      )
                    """,
                    (workspace_id, *edge_ids),
                )
            conn.execute(
                """
                DELETE FROM fragment_shingles
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM fragment_exact_index
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM runtime_lineage_state
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM runtime_source_binding_edges
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM analysis_cursors
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM resource_versions
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.execute(
                """
                DELETE FROM sink_candidates
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )

    def list_source_binding_edges(self, analysis_run_id: str) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_node_kind,
                    dst_node_id,
                    relation,
                    evidence_level,
                    method,
                    score,
                    reason
                FROM source_binding_edges
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            ).fetchall()
        return [
            FlowEdge(
                edge_id=row[0],
                src_node_kind=row[1],
                src_node_id=row[2],
                dst_node_kind=row[3],
                dst_node_id=row[4],
                relation=row[5],
                evidence_level=row[6],
                method=row[7],
                score=row[8],
                reason=row[9],
            )
            for row in rows
        ]

    def list_analysis_runs(self) -> list[AnalysisRun]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    analysis_run_id,
                    detector_version,
                    config_json,
                    started_at,
                    completed_at,
                    workspace_id,
                    session_id
                FROM analysis_runs
                ORDER BY started_at DESC, rowid DESC
                """
            ).fetchall()
        return [
            AnalysisRun(
                analysis_run_id=row[0],
                detector_version=row[1],
                config_json=row[2],
                started_at=row[3],
                completed_at=row[4],
                workspace_id=row[5],
                session_id=row[6],
            )
            for row in rows
        ]

    def list_analysis_runs_for_workspace(
        self,
        workspace_id: str,
        *,
        completed_only: bool = False,
    ) -> list[AnalysisRun]:
        completed_clause = "AND completed_at IS NOT NULL" if completed_only else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    analysis_run_id,
                    detector_version,
                    config_json,
                    started_at,
                    completed_at,
                    workspace_id,
                    session_id
                FROM analysis_runs
                WHERE workspace_id = ?
                  {completed_clause}
                ORDER BY started_at DESC, rowid DESC
                """,
                (workspace_id,),
            ).fetchall()
        return [AnalysisRun(*row) for row in rows]

    def get_analysis_run(self, analysis_run_id: str) -> AnalysisRun | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    analysis_run_id,
                    detector_version,
                    config_json,
                    started_at,
                    completed_at,
                    workspace_id,
                    session_id
                FROM analysis_runs
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            ).fetchone()
        if row is None:
            return None
        return AnalysisRun(
            analysis_run_id=row[0],
            detector_version=row[1],
            config_json=row[2],
            started_at=row[3],
            completed_at=row[4],
            workspace_id=row[5],
            session_id=row[6],
        )

    def get_runtime_analysis_run(
        self,
        analysis_run_id: str,
        *,
        workspace_id: str,
        session_id: str,
    ) -> AnalysisRun:
        run = self.get_analysis_run(analysis_run_id)
        if (
            run is None
            or run.workspace_id != workspace_id
            or run.session_id != session_id
        ):
            raise ValueError("analysis run does not match runtime scope")
        return run

    def list_lineage_assignments(
        self,
        analysis_run_id: str,
    ) -> list[LineageAssignment]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    analysis_run_id,
                    source_node_kind,
                    source_node_id,
                    node_kind,
                    node_id,
                    best_path_score,
                    predecessor_edge_id,
                    hop_count
                FROM lineage_assignments
                WHERE analysis_run_id = ?
                ORDER BY source_node_kind, source_node_id, hop_count, node_kind, node_id
                """,
                (analysis_run_id,),
            ).fetchall()
        return [
            LineageAssignment(
                analysis_run_id=row[0],
                source_node_kind=row[1],
                source_node_id=row[2],
                node_kind=row[3],
                node_id=row[4],
                best_path_score=row[5],
                predecessor_edge_id=row[6],
                hop_count=row[7],
            )
            for row in rows
        ]

    def list_protected_sources(self) -> list[ProtectedSource]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    source_id,
                    path,
                    source_type,
                    sensitivity,
                    policy_tags_json,
                    workspace_id,
                    source_key,
                    selector_json
                FROM protected_sources
                ORDER BY source_id
                """
            ).fetchall()
        return [_protected_source_from_row(row) for row in rows]

    def list_source_chunks(self) -> list[SourceChunk]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    chunk_id,
                    source_id,
                    ordinal,
                    text,
                    normalized_text,
                    text_hash,
                    shingle_fingerprint,
                    token_count,
                    workspace_id
                FROM source_chunks
                ORDER BY source_id, ordinal
                """
            ).fetchall()
        return [_source_chunk_from_row(row) for row in rows]

    def list_protected_sources_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ProtectedSource]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    source_id,
                    path,
                    source_type,
                    sensitivity,
                    policy_tags_json,
                    workspace_id,
                    source_key,
                    selector_json
                FROM protected_sources
                WHERE workspace_id = ?
                ORDER BY source_key, source_id
                """,
                (workspace_id,),
            ).fetchall()
        return [_protected_source_from_row(row) for row in rows]

    def list_source_chunks_for_workspace(
        self,
        workspace_id: str,
    ) -> list[SourceChunk]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    chunk_id,
                    source_id,
                    ordinal,
                    text,
                    normalized_text,
                    text_hash,
                    shingle_fingerprint,
                    token_count,
                    workspace_id
                FROM source_chunks
                WHERE workspace_id = ?
                ORDER BY source_id, ordinal
                """,
                (workspace_id,),
            ).fetchall()
        return [_source_chunk_from_row(row) for row in rows]

    def list_source_chunks_for_workspace_ids(
        self,
        workspace_id: str,
        chunk_ids: tuple[str, ...],
        *,
        max_ids: int = 32,
        max_bytes_per_chunk: int = 32 * 1024,
        max_bytes_total: int = 128 * 1024,
    ) -> list[SourceChunkEvidence]:
        """Load only explicitly referenced source chunks for one workspace."""
        limits = (max_ids, max_bytes_per_chunk, max_bytes_total)
        if any(type(limit) is not int or limit <= 0 for limit in limits):
            raise ValueError("source chunk lookup limits must be positive integers")
        if not isinstance(workspace_id, str) or not workspace_id:
            raise ValueError("source chunk lookup requires a workspace id")
        if not isinstance(chunk_ids, tuple) or any(
            not isinstance(chunk_id, str)
            or not chunk_id
            or len(chunk_id.encode("utf-8", errors="surrogatepass")) > 1024
            for chunk_id in chunk_ids
        ):
            raise ValueError("source chunk ids must be bounded non-empty strings")
        distinct_ids = tuple(sorted(set(chunk_ids)))
        if len(distinct_ids) != len(chunk_ids):
            raise ValueError("source chunk ids must be unique")
        if len(distinct_ids) > max_ids:
            raise ValueError("source chunk lookup limit exceeded")
        if not distinct_ids:
            return []

        with self._connect_redaction_audit() as conn:
            conn.execute("BEGIN")
            return _load_bounded_source_chunk_evidence(
                conn,
                workspace_id,
                distinct_ids,
                max_ids=max_ids,
                max_bytes_per_chunk=max_bytes_per_chunk,
                max_bytes_total=max_bytes_total,
            )

    def list_resource_versions(self) -> list[ResourceVersion]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
                    workspace_id,
                    path,
                    content_hash,
                    sequence_no,
                    session_id,
                    origin_tool_use_id,
                    operation_id,
                    operation_index,
                    snapshot_id,
                    resource_state
                FROM resource_versions
                ORDER BY sequence_no, COALESCE(operation_index, -1), path, node_id
                """
            ).fetchall()
        return [
            ResourceVersion(
                node_id=row[0],
                workspace_id=_model_derived_workspace_id(row[1]),
                path=row[2],
                content_hash=row[3],
                sequence_no=row[4],
                session_id=row[5],
                origin_tool_use_id=row[6],
                operation_id=row[7],
                operation_index=row[8],
                snapshot_id=row[9],
                resource_state=row[10],
            )
            for row in rows
        ]

    def list_resource_versions_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ResourceVersion]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
                    workspace_id,
                    path,
                    content_hash,
                    sequence_no,
                    session_id,
                    origin_tool_use_id,
                    operation_id,
                    operation_index,
                    snapshot_id,
                    resource_state
                FROM resource_versions
                WHERE workspace_id = ?
                ORDER BY sequence_no, COALESCE(operation_index, -1), path, node_id
                """,
                (workspace_id,),
            ).fetchall()
        return [
            ResourceVersion(
                node_id=row[0],
                workspace_id=_model_derived_workspace_id(row[1]),
                path=row[2],
                content_hash=row[3],
                sequence_no=row[4],
                session_id=row[5],
                origin_tool_use_id=row[6],
                operation_id=row[7],
                operation_index=row[8],
                snapshot_id=row[9],
                resource_state=row[10],
            )
            for row in rows
        ]

    def list_resource_versions_for_session(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> list[ResourceVersion]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT node_id, path, content_hash, sequence_no, session_id,
                       origin_tool_use_id, operation_id, operation_index,
                       snapshot_id, resource_state, workspace_id
                FROM resource_versions
                WHERE workspace_id = ? AND session_id = ?
                ORDER BY sequence_no, COALESCE(operation_index, -1), path, node_id
                """,
                (workspace_id, session_id),
            ).fetchall()
        return [
            ResourceVersion(
                node_id=row[0],
                path=row[1],
                content_hash=row[2],
                sequence_no=row[3],
                session_id=row[4],
                origin_tool_use_id=row[5],
                operation_id=row[6],
                operation_index=row[7],
                snapshot_id=row[8],
                resource_state=row[9],
                workspace_id=_model_derived_workspace_id(row[10]),
            )
            for row in rows
        ]

    def list_sink_candidates(self) -> list[SinkCandidate]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
                    workspace_id,
                    sink_type,
                    label,
                    tool_name,
                    tool_use_id,
                    session_id,
                    sequence_no,
                    metadata_json
                FROM sink_candidates
                ORDER BY sequence_no, sink_type, node_id
                """
            ).fetchall()
        return [
            SinkCandidate(
                node_id=row[0],
                workspace_id=_model_derived_workspace_id(row[1]),
                sink_type=row[2],
                label=row[3],
                tool_name=row[4],
                tool_use_id=row[5],
                session_id=row[6],
                sequence_no=row[7],
                metadata=json.loads(row[8]),
            )
            for row in rows
        ]

    def list_sink_candidates_for_workspace(
        self,
        workspace_id: str,
    ) -> list[SinkCandidate]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
                    workspace_id,
                    sink_type,
                    label,
                    tool_name,
                    tool_use_id,
                    session_id,
                    sequence_no,
                    metadata_json
                FROM sink_candidates
                WHERE workspace_id = ?
                ORDER BY sequence_no, sink_type, node_id
                """,
                (workspace_id,),
            ).fetchall()
        return [
            SinkCandidate(
                node_id=row[0],
                workspace_id=_model_derived_workspace_id(row[1]),
                sink_type=row[2],
                label=row[3],
                tool_name=row[4],
                tool_use_id=row[5],
                session_id=row[6],
                sequence_no=row[7],
                metadata=json.loads(row[8]),
            )
            for row in rows
        ]

    def list_sink_candidates_for_session(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> list[SinkCandidate]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT node_id, sink_type, label, tool_name, tool_use_id,
                       session_id, sequence_no, metadata_json, workspace_id
                FROM sink_candidates
                WHERE workspace_id = ? AND session_id = ?
                ORDER BY sequence_no, sink_type, node_id
                """,
                (workspace_id, session_id),
            ).fetchall()
        return [
            SinkCandidate(
                node_id=row[0],
                sink_type=row[1],
                label=row[2],
                tool_name=row[3],
                tool_use_id=row[4],
                session_id=row[5],
                sequence_no=row[6],
                metadata=json.loads(row[7]),
                workspace_id=_model_derived_workspace_id(row[8]),
            )
            for row in rows
        ]

    def replace_runtime_lineage_state(
        self,
        session_id: str,
        sequence_no: int,
        assignments: list[LineageAssignment],
        *,
        workspace_id: str,
        analysis_run_id: str,
    ) -> None:
        _validate_assignment_run_ids(assignments, analysis_run_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            self._validate_runtime_analysis_run_owner(
                conn,
                analysis_run_id,
                workspace_id,
                session_id,
            )
            conn.execute(
                """
                DELETE FROM runtime_lineage_state
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            )
            conn.executemany(
                """
                INSERT INTO runtime_lineage_state (
                    workspace_id, session_id, source_node_kind, source_node_id,
                    node_kind, node_id, best_path_score, predecessor_edge_id,
                    hop_count, updated_sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        workspace_id,
                        session_id,
                        assignment.source_node_kind,
                        assignment.source_node_id,
                        assignment.node_kind,
                        assignment.node_id,
                        assignment.best_path_score,
                        assignment.predecessor_edge_id,
                        assignment.hop_count,
                        sequence_no,
                    )
                    for assignment in assignments
                ],
            )

    def upsert_runtime_source_binding_edges(
        self,
        session_id: str,
        edges: list[FlowEdge],
        *,
        workspace_id: str,
    ) -> None:
        if not edges:
            return
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            conn.executemany(
                """
                INSERT INTO runtime_source_binding_edges (
                    workspace_id, session_id, edge_id, src_node_kind, src_node_id,
                    dst_node_kind, dst_node_id, relation, evidence_level,
                    method, score, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, session_id, edge_id) DO UPDATE SET
                    src_node_kind = excluded.src_node_kind,
                    src_node_id = excluded.src_node_id,
                    dst_node_kind = excluded.dst_node_kind,
                    dst_node_id = excluded.dst_node_id,
                    relation = excluded.relation,
                    evidence_level = excluded.evidence_level,
                    method = excluded.method,
                    score = excluded.score,
                    reason = excluded.reason
                """,
                [
                    (workspace_id, session_id, *_flow_edge_values(edge))
                    for edge in edges
                ],
            )

    def list_runtime_source_binding_edges(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT edge_id, src_node_kind, src_node_id, dst_node_kind,
                       dst_node_id, relation, evidence_level, method, score, reason
                FROM runtime_source_binding_edges
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def upsert_runtime_lineage_state(
        self,
        session_id: str,
        sequence_no: int,
        assignments: list[LineageAssignment],
        *,
        workspace_id: str,
        analysis_run_id: str,
    ) -> None:
        _validate_assignment_run_ids(assignments, analysis_run_id)
        if not assignments:
            return
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            self._validate_runtime_analysis_run_owner(
                conn,
                analysis_run_id,
                workspace_id,
                session_id,
            )
            conn.executemany(
                """
                INSERT INTO runtime_lineage_state (
                    workspace_id, session_id, source_node_kind, source_node_id,
                    node_kind, node_id, best_path_score, predecessor_edge_id,
                    hop_count, updated_sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(
                    workspace_id, session_id, source_node_kind, source_node_id,
                    node_kind, node_id
                ) DO UPDATE SET
                    best_path_score = excluded.best_path_score,
                    predecessor_edge_id = excluded.predecessor_edge_id,
                    hop_count = excluded.hop_count,
                    updated_sequence_no = excluded.updated_sequence_no
                WHERE excluded.best_path_score > runtime_lineage_state.best_path_score
                """,
                [
                    (
                        workspace_id,
                        session_id,
                        assignment.source_node_kind,
                        assignment.source_node_id,
                        assignment.node_kind,
                        assignment.node_id,
                        assignment.best_path_score,
                        assignment.predecessor_edge_id,
                        assignment.hop_count,
                        sequence_no,
                    )
                    for assignment in assignments
                ],
            )

    def list_runtime_lineage_state(
        self,
        session_id: str,
        analysis_run_id: str,
        *,
        workspace_id: str,
    ) -> list[LineageAssignment]:
        with self._connect() as conn:
            self._validate_runtime_analysis_run_owner(
                conn,
                analysis_run_id,
                workspace_id,
                session_id,
            )
            rows = conn.execute(
                """
                SELECT source_node_kind, source_node_id, node_kind, node_id,
                       best_path_score, predecessor_edge_id, hop_count
                FROM runtime_lineage_state
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            ).fetchall()
        return [
            LineageAssignment(
                analysis_run_id=analysis_run_id,
                source_node_kind=row[0],
                source_node_id=row[1],
                node_kind=row[2],
                node_id=row[3],
                best_path_score=row[4],
                predecessor_edge_id=row[5],
                hop_count=row[6],
            )
            for row in rows
        ]

    def get_analysis_state(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM analysis_state WHERE key = ?",
                (key,),
            ).fetchone()
        return None if row is None else str(row[0])

    def set_analysis_state(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analysis_state (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, value),
            )

    def get_workspace_analysis_state(
        self,
        workspace_id: str,
        key: str,
    ) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT value
                FROM workspace_analysis_state
                WHERE workspace_id = ? AND key = ?
                """,
                (workspace_id, key),
            ).fetchone()
        return None if row is None else str(row[0])

    def set_workspace_analysis_state(
        self,
        workspace_id: str,
        key: str,
        value: str,
    ) -> None:
        with self._connect() as conn:
            self._set_workspace_analysis_state(
                conn,
                workspace_id,
                key,
                value,
            )

    def _set_workspace_analysis_state(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
        key: str,
        value: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO workspace_analysis_state (workspace_id, key, value)
            VALUES (?, ?, ?)
            ON CONFLICT(workspace_id, key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (workspace_id, key, value),
        )

    def get_analysis_cursor(
        self,
        session_id: str,
        *,
        workspace_id: str,
    ) -> AnalysisCursor | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT workspace_id, session_id, detector_version, source_digest,
                       last_sequence_no, status
                FROM analysis_cursors
                WHERE workspace_id = ? AND session_id = ?
                """,
                (workspace_id, session_id),
            ).fetchone()
        if row is None:
            return None
        return AnalysisCursor(
            workspace_id=row[0],
            session_id=row[1],
            detector_version=row[2],
            source_digest=row[3],
            last_sequence_no=row[4],
            status=row[5],
        )

    def upsert_analysis_cursor(self, cursor: AnalysisCursor) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(
                conn,
                cursor.workspace_id,
                cursor.session_id,
            )
            conn.execute(
                """
                INSERT INTO analysis_cursors (
                    workspace_id, session_id, detector_version, source_digest,
                    last_sequence_no, status
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, session_id) DO UPDATE SET
                    detector_version = excluded.detector_version,
                    source_digest = excluded.source_digest,
                    last_sequence_no = excluded.last_sequence_no,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    cursor.workspace_id,
                    cursor.session_id,
                    cursor.detector_version,
                    cursor.source_digest,
                    cursor.last_sequence_no,
                    cursor.status,
                ),
            )

    def upsert_fragment_shingles(
        self,
        session_id: str,
        contexts: list[ArtifactContext],
        shingles_by_fragment: dict[str, set[str]],
        *,
        workspace_id: str,
    ) -> None:
        if any(
            context.workspace_id != workspace_id
            or context.workspace_status != "ready"
            or context.session_id != session_id
            for context in contexts
        ):
            raise ValueError("fragment shingle context does not match write scope")
        rows = [
            (
                workspace_id,
                session_id,
                context.fragment.fragment_id,
                context.sequence_no,
                shingle,
            )
            for context in contexts
            for shingle in shingles_by_fragment.get(
                context.fragment.fragment_id,
                set(),
            )
        ]
        exact_rows = [
            (
                workspace_id,
                session_id,
                context.fragment.fragment_id,
                context.sequence_no,
                context.fragment.text_hash,
            )
            for context in contexts
        ]
        if not rows and not exact_rows:
            return
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            if rows:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO fragment_shingles (
                        workspace_id, session_id, fragment_id, sequence_no, shingle
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    rows,
                )
            if exact_rows:
                conn.executemany(
                    """
                    INSERT INTO fragment_exact_index (
                        workspace_id, session_id, fragment_id, sequence_no, text_hash
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(workspace_id, session_id, fragment_id) DO UPDATE SET
                        sequence_no = excluded.sequence_no,
                        text_hash = excluded.text_hash
                    """,
                    exact_rows,
                )

    def find_similarity_candidate_fragment_ids(
        self,
        session_id: str,
        text_hash: str,
        shingles: set[str],
        before_sequence_no: int,
        limit: int,
        *,
        workspace_id: str,
    ) -> list[str]:
        with self._connect() as conn:
            exact = [
                row[0]
                for row in conn.execute(
                    """
                    SELECT fragment_id
                    FROM fragment_exact_index
                    WHERE workspace_id = ?
                      AND session_id = ?
                      AND text_hash = ?
                      AND sequence_no < ?
                    ORDER BY sequence_no DESC, fragment_id DESC
                    LIMIT 1
                    """,
                    (workspace_id, session_id, text_hash, before_sequence_no),
                ).fetchall()
            ]
            if exact:
                return exact
            overlap: list[str] = []
            if shingles:
                values = sorted(shingles)
                placeholders = ",".join("?" for _ in values)
                overlap = [
                    row[0]
                    for row in conn.execute(
                        f"""
                        SELECT fragment_id, COUNT(*) AS overlap_count
                        FROM fragment_shingles
                        WHERE workspace_id = ? AND session_id = ?
                          AND sequence_no < ?
                          AND shingle IN ({placeholders})
                        GROUP BY fragment_id
                        ORDER BY overlap_count DESC, fragment_id
                        LIMIT ?
                        """,
                        (
                            workspace_id,
                            session_id,
                            before_sequence_no,
                            *values,
                            limit,
                        ),
                    ).fetchall()
                ]
        return list(dict.fromkeys(exact + overlap))

    def upsert_lineage_assignments(
        self,
        assignments: list[LineageAssignment],
        *,
        _connection: sqlite3.Connection | None = None,
    ) -> None:
        if not assignments:
            return
        analysis_run_ids = {
            assignment.analysis_run_id for assignment in assignments
        }
        if len(analysis_run_ids) != 1:
            raise ValueError("lineage assignments span multiple analysis runs")
        analysis_run_id = next(iter(analysis_run_ids))
        owns_connection = _connection is None
        connection_context = (
            self._connect() if owns_connection else nullcontext(_connection)
        )
        with connection_context as conn:
            if owns_connection:
                conn.execute("BEGIN IMMEDIATE")
            workspace_id, _ = self._validate_mutable_analysis_run(
                conn,
                analysis_run_id,
            )
            if workspace_id is not None:
                self._validate_analysis_node_owners(
                    conn,
                    workspace_id,
                    [
                        node
                        for assignment in assignments
                        for node in (
                            (
                                assignment.source_node_kind,
                                assignment.source_node_id,
                            ),
                            (assignment.node_kind, assignment.node_id),
                        )
                    ],
                )
            conn.executemany(
                """
                INSERT OR REPLACE INTO lineage_assignments (
                    analysis_run_id,
                    source_node_kind,
                    source_node_id,
                    node_kind,
                    node_id,
                    best_path_score,
                    predecessor_edge_id,
                    hop_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        assignment.analysis_run_id,
                        assignment.source_node_kind,
                        assignment.source_node_id,
                        assignment.node_kind,
                        assignment.node_id,
                        assignment.best_path_score,
                        assignment.predecessor_edge_id,
                        assignment.hop_count,
                    )
                    for assignment in assignments
                ],
            )

    def list_artifacts(self) -> list[ArtifactRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT artifact_id, event_id, role, text, text_hash, normalized_text, token_count
                FROM artifacts
                ORDER BY recorded_at, artifact_id
                """
            ).fetchall()
        return [
            ArtifactRecord(
                artifact_id=row[0],
                event_id=row[1],
                role=row[2],
                text=row[3],
                text_hash=row[4],
                normalized_text=row[5],
                token_count=row[6],
            )
            for row in rows
        ]

    def list_artifacts_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ArtifactRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    a.artifact_id,
                    a.event_id,
                    a.role,
                    a.text,
                    a.text_hash,
                    a.normalized_text,
                    a.token_count
                FROM artifacts AS a
                JOIN events AS e ON e.event_id = a.event_id
                WHERE e.workspace_id = ?
                  AND e.workspace_status = 'ready'
                ORDER BY e.sequence_no, a.recorded_at, a.artifact_id
                """,
                (workspace_id,),
            ).fetchall()
        return [ArtifactRecord(*row) for row in rows]

    def list_artifact_contexts(self) -> list[ArtifactContext]:
        return self._list_artifact_contexts_where("", ())

    def list_artifact_contexts_for_workspace(
        self,
        workspace_id: str,
    ) -> list[ArtifactContext]:
        return self._list_artifact_contexts_where(
            """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
            """,
            (workspace_id,),
        )

    def list_artifact_contexts_for_session(
        self,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ArtifactContext]:
        clause = "WHERE e.session_id = ?"
        params: tuple[object, ...] = (session_id,)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_artifact_contexts_where(clause, params)

    def list_artifact_contexts_for_scope(
        self,
        workspace_id: str,
        session_id: str,
        *,
        after_sequence_no: int | None = None,
        through_sequence_no: int | None = None,
    ) -> list[ArtifactContext]:
        clause = """
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND e.session_id = ?
        """
        params: tuple[object, ...] = (workspace_id, session_id)
        if after_sequence_no is not None:
            clause += " AND e.sequence_no > ?"
            params += (after_sequence_no,)
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_artifact_contexts_where(clause, params)

    def list_artifact_contexts_for_tool_uses(
        self,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ArtifactContext]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"WHERE e.session_id = ? AND e.tool_use_id IN ({placeholders})"
        params: tuple[object, ...] = (session_id, *sorted(tool_use_ids))
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_artifact_contexts_where(clause, params)

    def list_artifact_contexts_for_scope_tool_uses(
        self,
        workspace_id: str,
        session_id: str,
        tool_use_ids: set[str],
        *,
        through_sequence_no: int | None = None,
    ) -> list[ArtifactContext]:
        if not tool_use_ids:
            return []
        placeholders = ",".join("?" for _ in tool_use_ids)
        clause = f"""
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND e.session_id = ?
              AND e.tool_use_id IN ({placeholders})
        """
        params: tuple[object, ...] = (
            workspace_id,
            session_id,
            *sorted(tool_use_ids),
        )
        if through_sequence_no is not None:
            clause += " AND e.sequence_no <= ?"
            params += (through_sequence_no,)
        return self._list_artifact_contexts_where(clause, params)

    def list_artifact_contexts_by_fragment_ids(
        self,
        fragment_ids: list[str],
    ) -> list[ArtifactContext]:
        if not fragment_ids:
            return []
        placeholders = ",".join("?" for _ in fragment_ids)
        return self._list_artifact_contexts_where(
            f"WHERE f.fragment_id IN ({placeholders})",
            tuple(fragment_ids),
        )

    def list_artifact_contexts_for_scope_by_fragment_ids(
        self,
        workspace_id: str,
        session_id: str,
        fragment_ids: list[str] | set[str],
    ) -> list[ArtifactContext]:
        if not fragment_ids:
            return []
        contexts: list[ArtifactContext] = []
        ordered_ids = sorted(set(fragment_ids))
        for start in range(0, len(ordered_ids), 300):
            current_ids = ordered_ids[start : start + 300]
            placeholders = ",".join("?" for _ in current_ids)
            contexts.extend(
                self._list_artifact_contexts_where(
                    f"""
                    WHERE e.workspace_id = ?
                      AND e.workspace_status = 'ready'
                      AND e.session_id = ?
                      AND f.fragment_id IN ({placeholders})
                    """,
                    (workspace_id, session_id, *current_ids),
                )
            )
        return sorted(
            contexts,
            key=lambda context: (
                context.sequence_no,
                context.fragment.fragment_id,
            ),
        )

    def get_event_sequence_no(self, event_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT sequence_no FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None or row[0] is None:
            raise KeyError(f"event not found: {event_id}")
        return int(row[0])

    def get_event_session_id(self, event_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT session_id FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"event not found: {event_id}")
        return row[0]

    def get_workspace_analysis_input_revision(self, workspace_id: str) -> str:
        """Hash the DB evidence consumed by one offline workspace rebuild."""
        with self._connect() as conn:
            conn.execute("BEGIN")
            self._validate_registered_workspace(conn, workspace_id)
            return self._workspace_analysis_input_revision(conn, workspace_id)

    def _workspace_analysis_input_revision(
        self,
        conn: sqlite3.Connection,
        workspace_id: str,
    ) -> str:
        missing_root = conn.execute(
            """
            SELECT a.artifact_id
            FROM artifacts AS a
            JOIN events AS e ON e.event_id = a.event_id
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND NOT EXISTS (
                  SELECT 1
                  FROM artifact_fragments AS fragment
                  WHERE fragment.artifact_id = a.artifact_id
                    AND fragment.json_pointer = '/'
              )
            LIMIT 1
            """,
            (workspace_id,),
        ).fetchone()
        if missing_root is not None:
            raise ValueError(
                "workspace analysis evidence requires artifact fragment backfill"
            )

        digest = hashlib.sha256()
        digest.update(WORKSPACE_ANALYSIS_INPUT_REVISION_VERSION.encode("ascii"))
        digest.update(b"\n")
        queries = (
            (
                "workspace",
                """
                SELECT workspace_id, canonical_root, lexical_root, discovered_by
                FROM workspaces
                WHERE workspace_id = ?
                ORDER BY workspace_id
                """,
            ),
            (
                "events",
                """
                SELECT event_id, phase, session_id, turn_id, tool_use_id,
                       tool_name, cwd, model, permission_mode, transcript_path,
                       payload_json, sequence_no, stop_hook_active, workspace_id,
                       workspace_root, workspace_lexical_root,
                       workspace_execution_cwd, workspace_status,
                       workspace_source, workspace_namespace_id
                FROM events
                WHERE workspace_id = ? AND workspace_status = 'ready'
                ORDER BY sequence_no, event_id
                """,
            ),
            (
                "artifacts",
                """
                SELECT a.artifact_id, a.event_id, a.role, a.text,
                       a.text_hash, a.normalized_text, a.token_count
                FROM artifacts AS a
                JOIN events AS e ON e.event_id = a.event_id
                WHERE e.workspace_id = ? AND e.workspace_status = 'ready'
                ORDER BY a.artifact_id
                """,
            ),
            (
                "artifact_fragments",
                """
                SELECT fragment.fragment_id, fragment.artifact_id,
                       fragment.json_pointer, fragment.semantic_role,
                       fragment.text, fragment.text_hash,
                       fragment.normalized_text, fragment.token_count,
                       fragment.fragment_kind, fragment.parent_fragment_id,
                       fragment.operation_id
                FROM artifact_fragments AS fragment
                JOIN artifacts AS a ON a.artifact_id = fragment.artifact_id
                JOIN events AS e ON e.event_id = a.event_id
                WHERE e.workspace_id = ? AND e.workspace_status = 'ready'
                ORDER BY fragment.fragment_id
                """,
            ),
            (
                "tool_operations",
                """
                SELECT operation.operation_id, operation.event_id,
                       operation.artifact_id, operation.parent_fragment_id,
                       operation.session_id, operation.tool_use_id,
                       operation.tool_name, operation.adapter,
                       operation.operation_index, operation.operation_kind,
                       operation.source_path, operation.target_path,
                       operation.segment_index, operation.connector,
                       operation.content_fragment_id, operation.outcome,
                       operation.outcome_evidence
                FROM tool_operations AS operation
                JOIN events AS owner ON owner.event_id = operation.event_id
                WHERE owner.workspace_id = ? AND owner.workspace_status = 'ready'
                ORDER BY operation.operation_id
                """,
            ),
            (
                "tool_operation_outcomes",
                """
                SELECT outcome.post_event_id, outcome.operation_id,
                       outcome.session_id, outcome.tool_use_id,
                       outcome.outcome, outcome.outcome_evidence
                FROM tool_operation_outcomes AS outcome
                JOIN tool_operations AS operation
                  ON operation.operation_id = outcome.operation_id
                JOIN events AS owner ON owner.event_id = operation.event_id
                WHERE owner.workspace_id = ? AND owner.workspace_status = 'ready'
                ORDER BY outcome.operation_id, outcome.post_event_id
                """,
            ),
            (
                "resource_snapshots",
                """
                SELECT snapshot.snapshot_id, snapshot.post_event_id,
                       snapshot.operation_id, snapshot.session_id,
                       snapshot.tool_use_id, snapshot.path_role,
                       snapshot.requested_path, snapshot.workspace_root,
                       snapshot.lexical_path, snapshot.resource_state,
                       snapshot.capture_status, snapshot.file_kind,
                       snapshot.byte_size, snapshot.captured_bytes,
                       snapshot.content_sha256, snapshot.encoding,
                       snapshot.body_text, snapshot.error_code,
                       snapshot.duration_ms
                FROM resource_snapshots AS snapshot
                JOIN tool_operations AS operation
                  ON operation.operation_id = snapshot.operation_id
                JOIN events AS owner ON owner.event_id = operation.event_id
                WHERE owner.workspace_id = ? AND owner.workspace_status = 'ready'
                ORDER BY snapshot.snapshot_id
                """,
            ),
            (
                "protected_sources",
                """
                SELECT source_id, workspace_id, source_key, path, source_type,
                       sensitivity, policy_tags_json, selector_json
                FROM protected_sources
                WHERE workspace_id = ?
                ORDER BY source_id
                """,
            ),
            (
                "source_chunks",
                """
                SELECT chunk_id, source_id, workspace_id, ordinal, text,
                       normalized_text, text_hash, shingle_fingerprint,
                       token_count
                FROM source_chunks
                WHERE workspace_id = ?
                ORDER BY chunk_id
                """,
            ),
        )
        for label, query in queries:
            rows = conn.execute(query, (workspace_id,)).fetchall()
            _update_workspace_analysis_input_revision(digest, label, rows)
        return digest.hexdigest()

    def get_event_workspace_context(self, event_id: str) -> WorkspaceContext:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    workspace_id,
                    workspace_root,
                    workspace_lexical_root,
                    workspace_execution_cwd,
                    workspace_status,
                    workspace_source
                FROM events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"event not found: {event_id}")
        return WorkspaceContext(
            workspace_id=row[0],
            canonical_root=row[1],
            lexical_root=row[2],
            execution_cwd=row[3],
            status=row[4],
            discovered_by=row[5] or "legacy_unscoped",
        )

    def get_workspace(self, workspace_id: str) -> WorkspaceContext | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    workspace_id,
                    canonical_root,
                    lexical_root,
                    discovered_by
                FROM workspaces
                WHERE workspace_id = ?
                """,
                (workspace_id,),
            ).fetchone()
        return None if row is None else _workspace_context_from_registry_row(row)

    def get_workspace_by_canonical_root(
        self,
        canonical_root: str,
    ) -> WorkspaceContext | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    workspace_id,
                    canonical_root,
                    lexical_root,
                    discovered_by
                FROM workspaces
                WHERE canonical_root = ?
                """,
                (canonical_root,),
            ).fetchone()
        return None if row is None else _workspace_context_from_registry_row(row)

    def register_workspace(self, workspace: WorkspaceContext) -> None:
        """Persist an explicitly initialized workspace without fabricating an event."""
        if not workspace.ready:
            raise ValueError("only a ready workspace can be registered")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._upsert_workspace(conn, workspace)

    def list_workspaces(self) -> list[WorkspaceContext]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    workspace_id,
                    canonical_root,
                    lexical_root,
                    discovered_by
                FROM workspaces
                ORDER BY canonical_root
                """
            ).fetchall()
        return [_workspace_context_from_registry_row(row) for row in rows]

    def find_registered_workspace_root(self, cwd: str | None) -> str | None:
        """Return the longest registered root containing cwd without mutating the DB."""
        execution = resolve_workspace(cwd)
        if not execution.ready or execution.canonical_root is None:
            return None
        if not self.db_path.is_file():
            return None
        try:
            uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=0.05) as conn:
                rows = conn.execute(
                    """
                    SELECT canonical_root
                    FROM workspaces
                    ORDER BY LENGTH(canonical_root) DESC, canonical_root
                    """
                ).fetchall()
        except sqlite3.Error:
            return None
        for (registered_root,) in rows:
            try:
                if (
                    os.path.commonpath(
                        (registered_root, execution.canonical_root)
                    )
                    == registered_root
                ):
                    return str(registered_root)
            except (TypeError, ValueError):
                continue
        return None

    def get_runtime_analysis_scope(self, event_id: str) -> RuntimeAnalysisScope:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    e.event_id,
                    e.phase,
                    e.workspace_id,
                    e.workspace_root,
                    e.workspace_execution_cwd,
                    e.workspace_status,
                    e.session_id,
                    e.sequence_no,
                    w.canonical_root
                FROM events AS e
                LEFT JOIN workspaces AS w ON w.workspace_id = e.workspace_id
                WHERE e.event_id = ?
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"event not found: {event_id}")
        (
            stored_event_id,
            phase,
            workspace_id,
            workspace_root,
            execution_cwd,
            workspace_status,
            session_id,
            sequence_no,
            registry_root,
        ) = row
        if (
            workspace_status != "ready"
            or workspace_id is None
            or workspace_root is None
            or execution_cwd is None
            or session_id is None
            or sequence_no is None
            or registry_root is None
            or workspace_root != registry_root
            or make_workspace_id(workspace_root) != workspace_id
        ):
            raise ValueError("event is not eligible for runtime analysis")
        return RuntimeAnalysisScope(
            event_id=stored_event_id,
            phase=phase,
            workspace_id=workspace_id,
            canonical_root=workspace_root,
            execution_cwd=execution_cwd,
            session_id=session_id,
            sequence_no=int(sequence_no),
        )

    def list_event_execution_contexts(
        self,
        event_ids: set[str],
    ) -> dict[str, tuple[str, str | None, str | None, str | None, str | None]]:
        if not event_ids:
            return {}
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT event_id, phase, session_id, tool_use_id, tool_name, cwd
                FROM events
                WHERE event_id IN ({placeholders})
                """,
                tuple(sorted(event_ids)),
            ).fetchall()
        return {
            event_id: (phase, session_id, tool_use_id, tool_name, cwd)
            for event_id, phase, session_id, tool_use_id, tool_name, cwd in rows
        }

    def _list_artifact_contexts_where(
        self,
        where_clause: str,
        params: tuple[object, ...],
    ) -> list[ArtifactContext]:
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    f.fragment_id,
                    f.artifact_id,
                    f.json_pointer,
                    f.semantic_role,
                    f.text,
                    f.text_hash,
                    f.normalized_text,
                    f.token_count,
                    f.fragment_kind,
                    f.parent_fragment_id,
                    f.operation_id,
                    a.role,
                    e.event_id,
                    e.phase,
                    e.session_id,
                    e.turn_id,
                    e.tool_use_id,
                    e.tool_name,
                    e.cwd,
                    e.sequence_no,
                    e.workspace_id,
                    e.workspace_root,
                    e.workspace_lexical_root,
                    e.workspace_execution_cwd,
                    e.workspace_status
                FROM artifact_fragments AS f
                JOIN artifacts AS a ON a.artifact_id = f.artifact_id
                JOIN events AS e ON e.event_id = a.event_id
                {where_clause}
                ORDER BY e.sequence_no, f.fragment_id
                """,
                params,
            ).fetchall()
        return [
            ArtifactContext(
                fragment=ArtifactFragment(
                    fragment_id=row[0],
                    artifact_id=row[1],
                    json_pointer=row[2],
                    semantic_role=row[3],
                    text=row[4],
                    text_hash=row[5],
                    normalized_text=row[6],
                    token_count=row[7],
                    fragment_kind=row[8],
                    parent_fragment_id=row[9],
                    operation_id=row[10],
                ),
                artifact_role=row[11],
                event_id=row[12],
                phase=row[13],
                session_id=row[14],
                turn_id=row[15],
                tool_use_id=row[16],
                tool_name=row[17],
                cwd=row[18],
                sequence_no=row[19],
                workspace_id=row[20],
                workspace_root=row[21],
                workspace_lexical_root=row[22],
                workspace_execution_cwd=row[23],
                workspace_status=row[24],
            )
            for row in rows
        ]

    def _ensure_column(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _record_event_payload_metadata(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        payload_bytes: int,
        payload_sha256: str,
        sequence_no: int,
        redaction_event_kind: str,
        redaction_scope_sha256: str | None,
        post_input_observation: PostRedactionInputObservation,
    ) -> None:
        """Persist narrow event metadata without weakening the core event write."""
        if self._redaction_audit_available is not True:
            return
        metadata_sha256 = _event_payload_metadata_sha256(
            event_id=event_id,
            payload_bytes=payload_bytes,
            payload_sha256=payload_sha256,
            sequence_no=sequence_no,
            redaction_event_kind=redaction_event_kind,
            redaction_scope_sha256=redaction_scope_sha256,
            post_input_observation=post_input_observation,
        )
        values = (
            event_id,
            _EVENT_PAYLOAD_METADATA_VERSION,
            metadata_sha256,
            payload_bytes,
            payload_sha256,
            sequence_no,
            redaction_event_kind,
            redaction_scope_sha256,
            post_input_observation.status,
            post_input_observation.observer_version,
            post_input_observation.diagnostic_code,
            post_input_observation.profile_id,
            post_input_observation.profile_version,
            post_input_observation.profile_registry_version,
            post_input_observation.input_bytes,
            post_input_observation.input_sha256,
            post_input_observation.structure_sha256,
        )
        savepoint = "event_payload_metadata_write"
        conn.execute(f"SAVEPOINT {savepoint}")
        try:
            conn.execute(
                """
                INSERT INTO event_payload_metadata (
                    event_id,
                    metadata_version,
                    metadata_sha256,
                    payload_bytes,
                    payload_sha256,
                    sequence_no,
                    redaction_event_kind,
                    redaction_scope_sha256,
                    post_input_status,
                    post_input_observer_version,
                    post_input_diagnostic_code,
                    post_profile_id,
                    post_profile_version,
                    post_profile_registry_version,
                    post_input_bytes,
                    post_input_sha256,
                    post_structure_sha256
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                values,
            )
            stored_values = conn.execute(
                """
                SELECT
                    event_id,
                    metadata_version,
                    metadata_sha256,
                    payload_bytes,
                    payload_sha256,
                    sequence_no,
                    redaction_event_kind,
                    redaction_scope_sha256,
                    post_input_status,
                    post_input_observer_version,
                    post_input_diagnostic_code,
                    post_profile_id,
                    post_profile_version,
                    post_profile_registry_version,
                    post_input_bytes,
                    post_input_sha256,
                    post_structure_sha256
                FROM event_payload_metadata
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
            if stored_values != values:
                stored_metadata = _event_payload_metadata_from_row(
                    stored_values
                )
                if (
                    stored_metadata is None
                    or stored_metadata.event_id != event_id
                    or stored_metadata.payload_bytes != payload_bytes
                    or stored_metadata.payload_sha256 != payload_sha256
                    or stored_metadata.sequence_no != sequence_no
                    or stored_metadata.redaction_event_kind
                    != redaction_event_kind
                    or stored_metadata.redaction_scope_sha256
                    != redaction_scope_sha256
                ):
                    raise sqlite3.IntegrityError(
                        "event payload metadata replay mismatch"
                    )
        except sqlite3.Error:
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
            self._redaction_audit_available = False
        else:
            conn.execute(f"RELEASE {savepoint}")

    def _initialize_redaction_preview_audit(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        """Keep optional preview audit drift outside the core Hook boundary."""
        savepoint = "redaction_preview_audit_schema"
        conn.execute(f"SAVEPOINT {savepoint}")
        try:
            self._migrate_redaction_preview_audit(conn)
            self._migrate_redaction_decision_linkage(conn)
            self._migrate_event_payload_metadata(conn)
        except (RuntimeError, sqlite3.Error):
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
            self._redaction_audit_available = False
        else:
            conn.execute(f"RELEASE {savepoint}")
            self._redaction_audit_available = True

    def _migrate_redaction_preview_audit(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        """Create the immutable, hash-only redaction preview audit schema."""
        migration_key = "migration.redaction_preview_audit.v1"
        migration_complete = conn.execute(
            """
            SELECT 1
            FROM analysis_state
            WHERE key = ? AND value = 'complete'
            """,
            (migration_key,),
        ).fetchone() is not None
        existing_tables = {
            row[0]
            for row in conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN ('redaction_plans', 'redaction_targets')
                """
            ).fetchall()
        }
        if migration_complete:
            self._validate_redaction_preview_audit_schema(conn)
            return
        if existing_tables:
            self._validate_redaction_preview_audit_schema(conn)
            conn.execute(
                """
                INSERT INTO analysis_state (key, value)
                VALUES (?, 'complete')
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (migration_key,),
            )
            return
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redaction_plans (
                plan_id TEXT PRIMARY KEY,
                analysis_run_id TEXT NOT NULL,
                pre_event_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                tool_use_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                adapter TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                profile_registry_version TEXT NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('preview', 'enforce')),
                status TEXT NOT NULL CHECK (
                    status IN (
                        'eligible',
                        'rejected',
                        'rendered',
                        'post_confirmed',
                        'post_mismatch'
                    )
                ),
                planner_version TEXT NOT NULL,
                original_input_sha256 TEXT,
                rewritten_input_sha256 TEXT,
                structure_sha256_before TEXT,
                structure_sha256_after TEXT,
                critical_finding_count INTEGER NOT NULL CHECK (
                    critical_finding_count >= 0
                ),
                replacement_count INTEGER NOT NULL CHECK (
                    replacement_count >= 0
                    AND replacement_count <= critical_finding_count
                ),
                rejection_code TEXT,
                post_event_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rendered_at TEXT,
                confirmed_at TEXT,
                FOREIGN KEY (analysis_run_id)
                    REFERENCES analysis_runs (analysis_run_id),
                FOREIGN KEY (pre_event_id) REFERENCES events (event_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces (workspace_id),
                FOREIGN KEY (post_event_id) REFERENCES events (event_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redaction_targets (
                plan_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                finding_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                source_node_kind TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                sink_node_id TEXT NOT NULL,
                json_pointer TEXT NOT NULL,
                original_value_sha256 TEXT NOT NULL,
                replacement_profile TEXT NOT NULL,
                PRIMARY KEY (plan_id, ordinal),
                FOREIGN KEY (plan_id)
                    REFERENCES redaction_plans (plan_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_redaction_plans_event_version
            ON redaction_plans (
                workspace_id,
                pre_event_id,
                analysis_run_id,
                planner_version,
                profile_version,
                mode
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_redaction_plans_tool_use
            ON redaction_plans (
                workspace_id,
                session_id,
                tool_use_id,
                created_at DESC,
                plan_id
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_redaction_plans_analysis_run
            ON redaction_plans (
                analysis_run_id,
                created_at DESC,
                plan_id
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_redaction_plans_created
            ON redaction_plans (created_at, plan_id)
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_redaction_targets_finding
            ON redaction_targets (plan_id, finding_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_redaction_targets_decision
            ON redaction_targets (decision_id, plan_id, ordinal)
            """
        )
        self._validate_redaction_preview_audit_schema(conn)
        conn.execute(
            """
            INSERT INTO analysis_state (key, value)
            VALUES (?, 'complete')
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (migration_key,),
        )

    def _migrate_redaction_decision_linkage(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        """Create narrow immutable links for future REDACT decisions."""
        migration_key = "migration.redaction_decision_linkage.v1"
        migration_complete = conn.execute(
            """
            SELECT 1
            FROM analysis_state
            WHERE key = ? AND value = 'complete'
            """,
            (migration_key,),
        ).fetchone() is not None
        table_exists = conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'redaction_decision_links'
            """
        ).fetchone() is not None
        if migration_complete:
            self._validate_redaction_decision_linkage_schema(conn)
            return
        if not table_exists:
            conn.execute(
                f"""
                CREATE TABLE redaction_decision_links (
                    enforce_plan_id TEXT NOT NULL CHECK (
                        typeof(enforce_plan_id) = 'text'
                        AND length(enforce_plan_id) = 64
                        AND enforce_plan_id NOT GLOB '*[^0-9a-f]*'
                    ),
                    target_ordinal INTEGER NOT NULL CHECK (
                        typeof(target_ordinal) = 'integer'
                        AND target_ordinal BETWEEN 0 AND
                            {REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS - 1}
                    ),
                    preview_plan_id TEXT NOT NULL CHECK (
                        typeof(preview_plan_id) = 'text'
                        AND length(preview_plan_id) = 64
                        AND preview_plan_id NOT GLOB '*[^0-9a-f]*'
                        AND preview_plan_id != enforce_plan_id
                    ),
                    finding_id TEXT NOT NULL CHECK (
                        typeof(finding_id) = 'text'
                        AND length(finding_id) = 64
                        AND finding_id NOT GLOB '*[^0-9a-f]*'
                    ),
                    source_block_decision_id TEXT NOT NULL CHECK (
                        typeof(source_block_decision_id) = 'text'
                        AND length(source_block_decision_id) = 64
                        AND source_block_decision_id
                            NOT GLOB '*[^0-9a-f]*'
                    ),
                    derived_redact_decision_id TEXT NOT NULL CHECK (
                        typeof(derived_redact_decision_id) = 'text'
                        AND length(derived_redact_decision_id) = 64
                        AND derived_redact_decision_id
                            NOT GLOB '*[^0-9a-f]*'
                    ),
                    derivation_version TEXT NOT NULL CHECK (
                        typeof(derivation_version) = 'text'
                        AND derivation_version =
                            '{REDACTION_DECISION_DERIVATION_VERSION}'
                    ),
                    metadata_sha256 TEXT NOT NULL CHECK (
                        typeof(metadata_sha256) = 'text'
                        AND length(metadata_sha256) = 64
                        AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'
                    ),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (
                        typeof(created_at) = 'text'
                        AND length(created_at) BETWEEN 1 AND 64
                    ),
                    PRIMARY KEY (enforce_plan_id, target_ordinal),
                    FOREIGN KEY (enforce_plan_id, target_ordinal)
                        REFERENCES redaction_targets (plan_id, ordinal)
                        ON DELETE CASCADE,
                    FOREIGN KEY (preview_plan_id, target_ordinal)
                        REFERENCES redaction_targets (plan_id, ordinal)
                        ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX
                    idx_redaction_decision_links_preview_ordinal
                ON redaction_decision_links (
                    preview_plan_id, target_ordinal
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX idx_redaction_decision_links_finding
                ON redaction_decision_links (enforce_plan_id, finding_id)
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX idx_redaction_decision_links_source
                ON redaction_decision_links (
                    enforce_plan_id, source_block_decision_id
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX idx_redaction_decision_links_derived
                ON redaction_decision_links (
                    enforce_plan_id, derived_redact_decision_id
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX idx_redaction_decision_links_source_lookup
                ON redaction_decision_links (
                    source_block_decision_id,
                    enforce_plan_id,
                    target_ordinal
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX idx_redaction_decision_links_derived_lookup
                ON redaction_decision_links (
                    derived_redact_decision_id,
                    enforce_plan_id,
                    target_ordinal
                )
                """
            )
        self._validate_redaction_decision_linkage_schema(conn)
        conn.execute(
            """
            INSERT INTO analysis_state (key, value)
            VALUES (?, 'complete')
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (migration_key,),
        )

    def _migrate_event_payload_metadata(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        """Create sparse O(1) event metadata without legacy backfill."""
        migration_key = "migration.event_payload_metadata.v1"
        migration_complete = conn.execute(
            """
            SELECT 1
            FROM analysis_state
            WHERE key = ? AND value = 'complete'
            """,
            (migration_key,),
        ).fetchone() is not None
        table_exists = conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'event_payload_metadata'
            """
        ).fetchone() is not None
        if migration_complete:
            self._validate_event_payload_metadata_schema(conn)
            return
        if not table_exists:
            diagnostic_codes = ", ".join(
                f"'{code}'"
                for code in sorted(REDACTION_POST_INPUT_DIAGNOSTIC_CODES)
            )
            conn.execute(
                f"""
                CREATE TABLE event_payload_metadata (
                    event_id TEXT PRIMARY KEY NOT NULL,
                    metadata_version TEXT NOT NULL CHECK (
                        typeof(metadata_version) = 'text'
                        AND metadata_version =
                            '{_EVENT_PAYLOAD_METADATA_VERSION}'
                    ),
                    metadata_sha256 TEXT NOT NULL CHECK (
                        typeof(metadata_sha256) = 'text'
                        AND length(metadata_sha256) = 64
                        AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'
                    ),
                    payload_bytes INTEGER NOT NULL CHECK (
                        typeof(payload_bytes) = 'integer'
                        AND payload_bytes >= 0
                    ),
                    payload_sha256 TEXT NOT NULL CHECK (
                        typeof(payload_sha256) = 'text'
                        AND length(payload_sha256) = 64
                        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
                    ),
                    sequence_no INTEGER NOT NULL CHECK (
                        typeof(sequence_no) = 'integer'
                        AND sequence_no >= 1
                    ),
                    redaction_event_kind TEXT NOT NULL CHECK (
                        typeof(redaction_event_kind) = 'text'
                        AND redaction_event_kind IN (
                            'not_applicable',
                            'pre',
                            'post'
                        )
                    ),
                    redaction_scope_sha256 TEXT CHECK (
                        redaction_scope_sha256 IS NULL
                        OR (
                            typeof(redaction_scope_sha256) = 'text'
                            AND length(redaction_scope_sha256) = 64
                            AND redaction_scope_sha256
                                NOT GLOB '*[^0-9a-f]*'
                        )
                    ),
                    post_input_status TEXT NOT NULL CHECK (
                        typeof(post_input_status) = 'text'
                        AND post_input_status IN (
                            'not_applicable',
                            'captured',
                            'unobserved'
                        )
                    ),
                    post_input_observer_version TEXT,
                    post_input_diagnostic_code TEXT,
                    post_profile_id TEXT,
                    post_profile_version TEXT,
                    post_profile_registry_version TEXT,
                    post_input_bytes INTEGER,
                    post_input_sha256 TEXT,
                    post_structure_sha256 TEXT,
                    CHECK (
                        (
                            redaction_event_kind = 'not_applicable'
                            AND redaction_scope_sha256 IS NULL
                        )
                        OR (
                            redaction_event_kind IN ('pre', 'post')
                            AND redaction_scope_sha256 IS NOT NULL
                        )
                    ),
                    CHECK (
                        (
                            post_input_status = 'not_applicable'
                            AND redaction_event_kind != 'post'
                            AND post_input_observer_version IS NULL
                            AND post_input_diagnostic_code IS NULL
                            AND post_profile_id IS NULL
                            AND post_profile_version IS NULL
                            AND post_profile_registry_version IS NULL
                            AND post_input_bytes IS NULL
                            AND post_input_sha256 IS NULL
                            AND post_structure_sha256 IS NULL
                        )
                        OR (
                            post_input_status = 'unobserved'
                            AND redaction_event_kind = 'post'
                            AND typeof(post_input_observer_version) = 'text'
                            AND post_input_observer_version =
                                '{REDACTION_POST_INPUT_OBSERVER_VERSION}'
                            AND post_input_diagnostic_code IS NOT NULL
                            AND typeof(post_input_diagnostic_code) = 'text'
                            AND post_input_diagnostic_code IN (
                                {diagnostic_codes}
                            )
                            AND post_profile_id IS NULL
                            AND post_profile_version IS NULL
                            AND post_profile_registry_version IS NULL
                            AND post_input_bytes IS NULL
                            AND post_input_sha256 IS NULL
                            AND post_structure_sha256 IS NULL
                        )
                        OR (
                            post_input_status = 'captured'
                            AND redaction_event_kind = 'post'
                            AND payload_bytes <=
                                {REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES}
                            AND typeof(post_input_observer_version) = 'text'
                            AND post_input_observer_version =
                                '{REDACTION_POST_INPUT_OBSERVER_VERSION}'
                            AND post_input_diagnostic_code IS NULL
                            AND post_profile_id IS NOT NULL
                            AND typeof(post_profile_id) = 'text'
                            AND length(
                                CAST(post_profile_id AS BLOB)
                            ) BETWEEN 1 AND {MCP_TOOL_NAME_MAX_BYTES}
                            AND post_profile_version IS NOT NULL
                            AND typeof(post_profile_version) = 'text'
                            AND length(
                                CAST(post_profile_version AS BLOB)
                            ) BETWEEN 1 AND {MCP_TOOL_NAME_MAX_BYTES}
                            AND post_profile_registry_version IS NOT NULL
                            AND typeof(post_profile_registry_version) = 'text'
                            AND length(
                                CAST(post_profile_registry_version AS BLOB)
                            ) BETWEEN 1 AND {MCP_TOOL_NAME_MAX_BYTES}
                            AND post_input_bytes IS NOT NULL
                            AND typeof(post_input_bytes) = 'integer'
                            AND post_input_bytes BETWEEN 0 AND
                                {DEFAULT_MCP_INPUT_LIMITS.max_input_bytes}
                            AND post_input_sha256 IS NOT NULL
                            AND typeof(post_input_sha256) = 'text'
                            AND length(post_input_sha256) = 64
                            AND post_input_sha256
                                NOT GLOB '*[^0-9a-f]*'
                            AND post_structure_sha256 IS NOT NULL
                            AND typeof(post_structure_sha256) = 'text'
                            AND length(post_structure_sha256) = 64
                            AND post_structure_sha256
                                NOT GLOB '*[^0-9a-f]*'
                        )
                    ),
                    FOREIGN KEY (event_id) REFERENCES events (event_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX idx_event_payload_metadata_redaction_scope_sequence
                ON event_payload_metadata (
                    redaction_scope_sha256,
                    redaction_event_kind,
                    sequence_no,
                    event_id
                )
                WHERE redaction_scope_sha256 IS NOT NULL
                """
            )
        self._validate_event_payload_metadata_schema(conn)
        conn.execute(
            """
            INSERT INTO analysis_state (key, value)
            VALUES (?, 'complete')
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (migration_key,),
        )

    def _validate_event_payload_metadata_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        rows = conn.execute(
            "PRAGMA table_info(event_payload_metadata)"
        ).fetchall()
        actual = {
            row[1]: (str(row[2]).upper(), bool(row[3]), int(row[5]))
            for row in rows
        }
        expected = {
            "event_id": ("TEXT", True, 1),
            "metadata_version": ("TEXT", True, 0),
            "metadata_sha256": ("TEXT", True, 0),
            "payload_bytes": ("INTEGER", True, 0),
            "payload_sha256": ("TEXT", True, 0),
            "sequence_no": ("INTEGER", True, 0),
            "redaction_event_kind": ("TEXT", True, 0),
            "redaction_scope_sha256": ("TEXT", False, 0),
            "post_input_status": ("TEXT", True, 0),
            "post_input_observer_version": ("TEXT", False, 0),
            "post_input_diagnostic_code": ("TEXT", False, 0),
            "post_profile_id": ("TEXT", False, 0),
            "post_profile_version": ("TEXT", False, 0),
            "post_profile_registry_version": ("TEXT", False, 0),
            "post_input_bytes": ("INTEGER", False, 0),
            "post_input_sha256": ("TEXT", False, 0),
            "post_structure_sha256": ("TEXT", False, 0),
        }
        if actual != expected:
            raise RuntimeError(
                "redaction audit schema mismatch: event_payload_metadata"
            )
        table_sql_row = conn.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'event_payload_metadata'
            """
        ).fetchone()
        table_sql = "" if table_sql_row is None else str(table_sql_row[0])
        normalized_table_sql = "".join(table_sql.casefold().split())
        if re.search(
            r"CHECK\s*\(\s*typeof\s*\(\s*payload_bytes\s*\)\s*"
            r"=\s*'integer'\s+AND\s+payload_bytes\s*>=\s*0\s*\)",
            table_sql,
            flags=re.IGNORECASE,
        ) is None:
            raise RuntimeError(
                "redaction audit payload byte constraint mismatch"
            )
        required_sql_fragments = {
            "typeof(metadata_version)='text'",
            f"metadata_version='{_EVENT_PAYLOAD_METADATA_VERSION}'",
            "typeof(metadata_sha256)='text'",
            "length(metadata_sha256)=64",
            "metadata_sha256notglob'*[^0-9a-f]*'",
            "typeof(payload_sha256)='text'",
            "length(payload_sha256)=64",
            "payload_sha256notglob'*[^0-9a-f]*'",
            "sequence_no>=1",
            "typeof(redaction_event_kind)='text'",
            "redaction_event_kindin('not_applicable','pre','post')",
            "typeof(redaction_scope_sha256)='text'",
            "typeof(post_input_status)='text'",
            "post_input_statusin('not_applicable','captured','unobserved')",
            (
                "post_input_observer_version="
                f"'{REDACTION_POST_INPUT_OBSERVER_VERSION}'"
            ),
            "post_input_status='not_applicable'",
            "post_input_status='unobserved'",
            "post_input_status='captured'",
            "typeof(post_profile_id)='text'",
            "typeof(post_profile_version)='text'",
            "typeof(post_profile_registry_version)='text'",
            "typeof(post_input_sha256)='text'",
            "post_input_sha256notglob'*[^0-9a-f]*'",
            "typeof(post_structure_sha256)='text'",
            "post_structure_sha256notglob'*[^0-9a-f]*'",
        }
        required_sql_fragments.update(
            f"'{code}'" for code in REDACTION_POST_INPUT_DIAGNOSTIC_CODES
        )
        if any(
            fragment.casefold() not in normalized_table_sql
            for fragment in required_sql_fragments
        ):
            raise RuntimeError(
                "redaction audit event metadata constraint mismatch"
            )
        foreign_keys = conn.execute(
            "PRAGMA foreign_key_list(event_payload_metadata)"
        ).fetchall()
        if not any(
            row[2] == "events" and row[3] == "event_id" and row[4] == "event_id"
            for row in foreign_keys
        ):
            raise RuntimeError(
                "redaction audit payload metadata owner mismatch"
            )
        index_row = conn.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'index'
              AND name = 'idx_event_payload_metadata_redaction_scope_sequence'
            """
        ).fetchone()
        index_sql = "" if index_row is None else str(index_row[0])
        normalized_index_sql = "".join(index_sql.casefold().split())
        if (
            "on event_payload_metadata (".replace(" ", "")
            not in normalized_index_sql
            or "(redaction_scope_sha256,redaction_event_kind,sequence_no,event_id)"
            not in normalized_index_sql
            or "whereredaction_scope_sha256isnotnull"
            not in normalized_index_sql
        ):
            raise RuntimeError(
                "redaction audit event metadata index mismatch"
            )

    def _validate_redaction_decision_linkage_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        rows = conn.execute(
            "PRAGMA table_info(redaction_decision_links)"
        ).fetchall()
        actual = {
            row[1]: (str(row[2]).upper(), bool(row[3]), int(row[5]))
            for row in rows
        }
        expected = {
            "enforce_plan_id": ("TEXT", True, 1),
            "target_ordinal": ("INTEGER", True, 2),
            "preview_plan_id": ("TEXT", True, 0),
            "finding_id": ("TEXT", True, 0),
            "source_block_decision_id": ("TEXT", True, 0),
            "derived_redact_decision_id": ("TEXT", True, 0),
            "derivation_version": ("TEXT", True, 0),
            "metadata_sha256": ("TEXT", True, 0),
            "created_at": ("TEXT", True, 0),
        }
        if actual != expected:
            raise RuntimeError(
                "redaction audit schema mismatch: redaction_decision_links"
            )
        created_at_row = next(
            (row for row in rows if row[1] == "created_at"),
            None,
        )
        if created_at_row is None or created_at_row[4] != "CURRENT_TIMESTAMP":
            raise RuntimeError(
                "redaction audit decision linkage default mismatch"
            )

        table_sql_row = conn.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'redaction_decision_links'
            """
        ).fetchone()
        table_sql = "" if table_sql_row is None else str(table_sql_row[0])
        normalized_table_sql = "".join(table_sql.casefold().split())
        required_sql_fragments = {
            "typeof(enforce_plan_id)='text'",
            "length(enforce_plan_id)=64",
            "enforce_plan_idnotglob'*[^0-9a-f]*'",
            "typeof(target_ordinal)='integer'",
            (
                "target_ordinalbetween0and"
                f"{REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS - 1}"
            ),
            "typeof(preview_plan_id)='text'",
            "length(preview_plan_id)=64",
            "preview_plan_idnotglob'*[^0-9a-f]*'",
            "preview_plan_id!=enforce_plan_id",
            "typeof(finding_id)='text'",
            "length(finding_id)=64",
            "finding_idnotglob'*[^0-9a-f]*'",
            "typeof(source_block_decision_id)='text'",
            "length(source_block_decision_id)=64",
            "source_block_decision_idnotglob'*[^0-9a-f]*'",
            "typeof(derived_redact_decision_id)='text'",
            "length(derived_redact_decision_id)=64",
            "derived_redact_decision_idnotglob'*[^0-9a-f]*'",
            "typeof(derivation_version)='text'",
            (
                "derivation_version="
                f"'{REDACTION_DECISION_DERIVATION_VERSION}'"
            ),
            "typeof(metadata_sha256)='text'",
            "length(metadata_sha256)=64",
            "metadata_sha256notglob'*[^0-9a-f]*'",
            "typeof(created_at)='text'",
            "length(created_at)between1and64",
        }
        if any(
            fragment.casefold() not in normalized_table_sql
            for fragment in required_sql_fragments
        ):
            raise RuntimeError(
                "redaction audit decision linkage constraint mismatch"
            )

        expected_indexes = {
            "idx_redaction_decision_links_preview_ordinal": (
                True,
                ("preview_plan_id", "target_ordinal"),
            ),
            "idx_redaction_decision_links_finding": (
                True,
                ("enforce_plan_id", "finding_id"),
            ),
            "idx_redaction_decision_links_source": (
                True,
                ("enforce_plan_id", "source_block_decision_id"),
            ),
            "idx_redaction_decision_links_derived": (
                True,
                ("enforce_plan_id", "derived_redact_decision_id"),
            ),
            "idx_redaction_decision_links_source_lookup": (
                False,
                (
                    "source_block_decision_id",
                    "enforce_plan_id",
                    "target_ordinal",
                ),
            ),
            "idx_redaction_decision_links_derived_lookup": (
                False,
                (
                    "derived_redact_decision_id",
                    "enforce_plan_id",
                    "target_ordinal",
                ),
            ),
        }
        indexes = {
            row[1]: bool(row[2])
            for row in conn.execute(
                "PRAGMA index_list(redaction_decision_links)"
            ).fetchall()
        }
        for index_name, (unique, columns) in expected_indexes.items():
            if indexes.get(index_name) != unique:
                raise RuntimeError(
                    "redaction audit decision linkage index mismatch"
                )
            actual_columns = tuple(
                row[2]
                for row in conn.execute(
                    f"PRAGMA index_info({index_name})"
                ).fetchall()
            )
            if actual_columns != columns:
                raise RuntimeError(
                    "redaction audit decision linkage index mismatch"
                )

        foreign_key_rows = conn.execute(
            "PRAGMA foreign_key_list(redaction_decision_links)"
        ).fetchall()
        grouped_foreign_keys: dict[int, list[tuple[int, str, str, str, str]]] = {}
        for row in foreign_key_rows:
            grouped_foreign_keys.setdefault(int(row[0]), []).append(
                (int(row[1]), str(row[2]), str(row[3]), str(row[4]), str(row[6]))
            )
        foreign_keys = {
            (
                tuple(item[2] for item in sorted(group)),
                tuple(item[3] for item in sorted(group)),
                tuple(item[1] for item in sorted(group)),
                tuple(item[4] for item in sorted(group)),
            )
            for group in grouped_foreign_keys.values()
        }
        expected_foreign_keys = {
            (
                ("enforce_plan_id", "target_ordinal"),
                ("plan_id", "ordinal"),
                ("redaction_targets", "redaction_targets"),
                ("CASCADE", "CASCADE"),
            ),
            (
                ("preview_plan_id", "target_ordinal"),
                ("plan_id", "ordinal"),
                ("redaction_targets", "redaction_targets"),
                ("CASCADE", "CASCADE"),
            ),
        }
        if foreign_keys != expected_foreign_keys:
            raise RuntimeError(
                "redaction audit decision linkage owner mismatch"
            )

    def _validate_redaction_preview_audit_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        expected_columns = {
            "redaction_plans": {
                "plan_id",
                "analysis_run_id",
                "pre_event_id",
                "workspace_id",
                "session_id",
                "tool_use_id",
                "tool_name",
                "adapter",
                "profile_id",
                "profile_version",
                "profile_registry_version",
                "mode",
                "status",
                "planner_version",
                "original_input_sha256",
                "rewritten_input_sha256",
                "structure_sha256_before",
                "structure_sha256_after",
                "critical_finding_count",
                "replacement_count",
                "rejection_code",
                "post_event_id",
                "created_at",
                "rendered_at",
                "confirmed_at",
            },
            "redaction_targets": {
                "plan_id",
                "ordinal",
                "finding_id",
                "decision_id",
                "source_node_kind",
                "source_node_id",
                "sink_node_id",
                "json_pointer",
                "original_value_sha256",
                "replacement_profile",
            },
        }
        expected_primary_keys = {
            "redaction_plans": ("plan_id",),
            "redaction_targets": ("plan_id", "ordinal"),
        }
        for table, expected in expected_columns.items():
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            if {row[1] for row in rows} != expected:
                raise RuntimeError(f"redaction audit schema mismatch: {table}")
            actual_key = tuple(
                row[1]
                for row in sorted(
                    (row for row in rows if row[5]),
                    key=lambda row: row[5],
                )
            )
            if actual_key != expected_primary_keys[table]:
                raise RuntimeError(f"redaction audit primary key mismatch: {table}")

        expected_indexes = {
            "idx_redaction_plans_event_version": (
                True,
                (
                    "workspace_id",
                    "pre_event_id",
                    "analysis_run_id",
                    "planner_version",
                    "profile_version",
                    "mode",
                ),
            ),
            "idx_redaction_plans_tool_use": (
                False,
                (
                    "workspace_id",
                    "session_id",
                    "tool_use_id",
                    "created_at",
                    "plan_id",
                ),
            ),
            "idx_redaction_plans_analysis_run": (
                False,
                ("analysis_run_id", "created_at", "plan_id"),
            ),
            "idx_redaction_plans_created": (
                False,
                ("created_at", "plan_id"),
            ),
            "idx_redaction_targets_finding": (
                True,
                ("plan_id", "finding_id"),
            ),
            "idx_redaction_targets_decision": (
                False,
                ("decision_id", "plan_id", "ordinal"),
            ),
        }
        table_indexes = {
            row[1]: bool(row[2])
            for table in expected_columns
            for row in conn.execute(f"PRAGMA index_list({table})").fetchall()
        }
        for index, (unique, columns) in expected_indexes.items():
            if table_indexes.get(index) != unique:
                raise RuntimeError(f"redaction audit index mismatch: {index}")
            actual_columns = tuple(
                row[2]
                for row in conn.execute(f"PRAGMA index_info({index})").fetchall()
            )
            if actual_columns != columns:
                raise RuntimeError(f"redaction audit index mismatch: {index}")

    def _migrate_information_flow_edges(self, conn: sqlite3.Connection) -> None:
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(information_flow_edges)"
            ).fetchall()
        }
        if "analysis_run_id" not in columns:
            return

        # artifact間グラフは再構築可能な派生データなので、旧試作スキーマは置換する。
        conn.execute("DROP TABLE information_flow_edges")
        conn.execute(
            """
            CREATE TABLE information_flow_edges (
                edge_id TEXT PRIMARY KEY,
                src_node_kind TEXT NOT NULL,
                src_node_id TEXT NOT NULL,
                dst_node_kind TEXT NOT NULL,
                dst_node_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                evidence_level TEXT NOT NULL,
                method TEXT NOT NULL,
                score REAL NOT NULL,
                reason TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            "DELETE FROM analysis_state WHERE key LIKE 'artifact_graph_%'"
        )

    def _migrate_lineage_assignments(self, conn: sqlite3.Connection) -> None:
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(lineage_assignments)"
            ).fetchall()
        }
        if "source_chunk_id" not in columns:
            return

        # lineageは解析runごとの派生データなので、source node一般化時に再生成する。
        conn.execute("DROP TABLE lineage_assignments")
        conn.execute(
            """
            CREATE TABLE lineage_assignments (
                analysis_run_id TEXT NOT NULL,
                source_node_kind TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                node_kind TEXT NOT NULL,
                node_id TEXT NOT NULL,
                best_path_score REAL NOT NULL,
                predecessor_edge_id TEXT,
                hop_count INTEGER NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (
                    analysis_run_id,
                    source_node_kind,
                    source_node_id,
                    node_kind,
                    node_id
                ),
                FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs (analysis_run_id)
            )
            """
        )

    def _migrate_workspace_analysis_scope(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        migration_key = "migration.workspace_analysis_scope.v1"
        migration_complete = conn.execute(
            "SELECT 1 FROM analysis_state WHERE key = ? AND value = 'complete'",
            (migration_key,),
        ).fetchone() is not None
        if migration_complete:
            try:
                self._validate_workspace_analysis_schema(conn)
            except RuntimeError:
                # runtime派生tableはraw evidenceから再生成できるため、
                # markerとschemaが不整合なら推測修復せず再作成する。
                pass
            else:
                return

        # これらはraw hook evidenceから再構築可能で、旧session-only rowを
        # workspaceへ推測割当すると誤taintになるため移行せず破棄する。
        for table in (
            "information_flow_edge_scopes",
            "information_flow_edges",
            "runtime_lineage_state",
            "runtime_source_binding_edges",
            "fragment_shingles",
            "fragment_exact_index",
            "analysis_cursors",
            "resource_versions",
            "sink_candidates",
            "workspace_analysis_state",
        ):
            conn.execute(f"DROP TABLE IF EXISTS {table}")

        conn.execute(
            """
            CREATE TABLE workspace_analysis_state (
                workspace_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, key)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE information_flow_edges (
                workspace_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                src_node_kind TEXT NOT NULL,
                src_node_id TEXT NOT NULL,
                dst_node_kind TEXT NOT NULL,
                dst_node_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                evidence_level TEXT NOT NULL,
                method TEXT NOT NULL,
                score REAL NOT NULL,
                reason TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, edge_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE information_flow_edge_scopes (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                PRIMARY KEY (workspace_id, session_id, edge_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE resource_versions (
                workspace_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                path TEXT NOT NULL,
                content_hash TEXT,
                sequence_no INTEGER NOT NULL,
                session_id TEXT,
                origin_tool_use_id TEXT,
                operation_id TEXT,
                operation_index INTEGER,
                snapshot_id TEXT,
                resource_state TEXT NOT NULL DEFAULT 'present',
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, node_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE sink_candidates (
                workspace_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                sink_type TEXT NOT NULL,
                label TEXT NOT NULL,
                tool_name TEXT,
                tool_use_id TEXT,
                session_id TEXT,
                sequence_no INTEGER NOT NULL,
                metadata_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, node_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE analysis_cursors (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                detector_version TEXT NOT NULL,
                source_digest TEXT NOT NULL,
                last_sequence_no INTEGER NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, session_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE fragment_shingles (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                fragment_id TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                shingle TEXT NOT NULL,
                PRIMARY KEY (workspace_id, session_id, fragment_id, shingle)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE fragment_exact_index (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                fragment_id TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                text_hash TEXT NOT NULL,
                PRIMARY KEY (workspace_id, session_id, fragment_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE runtime_lineage_state (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_node_kind TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                node_kind TEXT NOT NULL,
                node_id TEXT NOT NULL,
                best_path_score REAL NOT NULL,
                predecessor_edge_id TEXT,
                hop_count INTEGER NOT NULL,
                updated_sequence_no INTEGER NOT NULL,
                PRIMARY KEY (
                    workspace_id,
                    session_id,
                    source_node_kind,
                    source_node_id,
                    node_kind,
                    node_id
                )
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE runtime_source_binding_edges (
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                src_node_kind TEXT NOT NULL,
                src_node_id TEXT NOT NULL,
                dst_node_kind TEXT NOT NULL,
                dst_node_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                evidence_level TEXT NOT NULL,
                method TEXT NOT NULL,
                score REAL NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (workspace_id, session_id, edge_id)
            )
            """
        )
        conn.execute(
            "DELETE FROM analysis_state WHERE key LIKE 'artifact_graph_%'"
        )
        conn.execute(
            """
            INSERT INTO analysis_state (key, value)
            VALUES (?, 'complete')
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (migration_key,),
        )
        self._validate_workspace_analysis_schema(conn)

    def _validate_workspace_analysis_schema(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        required_columns = {
            "information_flow_edges": {
                "workspace_id", "edge_id", "src_node_kind", "src_node_id",
                "dst_node_kind", "dst_node_id", "relation", "evidence_level",
                "method", "score", "reason", "recorded_at",
            },
            "information_flow_edge_scopes": {
                "workspace_id", "session_id", "edge_id", "sequence_no",
            },
            "resource_versions": {
                "workspace_id", "node_id", "path", "content_hash",
                "sequence_no", "session_id", "origin_tool_use_id",
                "operation_id", "operation_index", "snapshot_id",
                "resource_state", "recorded_at",
            },
            "sink_candidates": {
                "workspace_id", "node_id", "sink_type", "label", "tool_name",
                "tool_use_id", "session_id", "sequence_no", "metadata_json",
                "recorded_at",
            },
            "analysis_cursors": {
                "workspace_id", "session_id", "detector_version",
                "source_digest", "last_sequence_no", "status", "updated_at",
            },
            "fragment_shingles": {
                "workspace_id", "session_id", "fragment_id", "sequence_no",
                "shingle",
            },
            "fragment_exact_index": {
                "workspace_id", "session_id", "fragment_id", "sequence_no",
                "text_hash",
            },
            "runtime_lineage_state": {
                "workspace_id", "session_id", "source_node_kind",
                "source_node_id", "node_kind", "node_id", "best_path_score",
                "predecessor_edge_id", "hop_count", "updated_sequence_no",
            },
            "runtime_source_binding_edges": {
                "workspace_id", "session_id", "edge_id", "src_node_kind",
                "src_node_id", "dst_node_kind", "dst_node_id", "relation",
                "evidence_level", "method", "score", "reason",
            },
            "workspace_analysis_state": {
                "workspace_id", "key", "value", "updated_at",
            },
        }
        expected_primary_keys = {
            "information_flow_edges": ("workspace_id", "edge_id"),
            "information_flow_edge_scopes": (
                "workspace_id",
                "session_id",
                "edge_id",
            ),
            "resource_versions": ("workspace_id", "node_id"),
            "sink_candidates": ("workspace_id", "node_id"),
            "analysis_cursors": ("workspace_id", "session_id"),
            "fragment_shingles": (
                "workspace_id",
                "session_id",
                "fragment_id",
                "shingle",
            ),
            "fragment_exact_index": (
                "workspace_id",
                "session_id",
                "fragment_id",
            ),
            "runtime_lineage_state": (
                "workspace_id",
                "session_id",
                "source_node_kind",
                "source_node_id",
                "node_kind",
                "node_id",
            ),
            "runtime_source_binding_edges": (
                "workspace_id",
                "session_id",
                "edge_id",
            ),
            "workspace_analysis_state": ("workspace_id", "key"),
        }
        for table, expected_key in expected_primary_keys.items():
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            columns = {row[1]: row for row in rows}
            actual_key = tuple(
                row[1]
                for row in sorted(
                    (row for row in rows if row[5]),
                    key=lambda row: row[5],
                )
            )
            if (
                not required_columns[table].issubset(columns)
                or actual_key != expected_key
            ):
                raise RuntimeError(
                    f"workspace analysis schema mismatch: {table}"
                )
            if columns["workspace_id"][3] != 1:
                raise RuntimeError(
                    f"workspace analysis owner must be required: {table}"
                )

    def _backfill_event_sequence_numbers(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT event_id
            FROM events
            WHERE sequence_no IS NULL
            ORDER BY recorded_at, rowid
            """
        ).fetchall()
        next_sequence = self._next_sequence_no(conn)
        for offset, (event_id,) in enumerate(rows):
            conn.execute(
                "UPDATE events SET sequence_no = ? WHERE event_id = ?",
                (next_sequence + offset, event_id),
            )

    def _backfill_event_workspaces(self, conn: sqlite3.Connection) -> None:
        migration_key = "migration.workspace_identity.v1"
        migration_complete = conn.execute(
            "SELECT 1 FROM analysis_state WHERE key = ?",
            (migration_key,),
        ).fetchone() is not None
        if migration_complete:
            has_legacy_rows = conn.execute(
                """
                SELECT 1
                FROM events
                WHERE workspace_status = 'legacy_unscoped'
                LIMIT 1
                """
            ).fetchone()
            if has_legacy_rows is None:
                return
        rows = conn.execute(
            """
            SELECT event_id, cwd
            FROM events
            WHERE workspace_status = 'legacy_unscoped'
            ORDER BY sequence_no, event_id
            """
        ).fetchall()
        resolved_by_cwd: dict[str | None, WorkspaceContext] = {}
        for event_id, cwd in rows:
            workspace = resolved_by_cwd.get(cwd)
            if workspace is None:
                workspace = resolve_workspace(
                    cwd,
                    discovered_by="legacy_cwd",
                )
                resolved_by_cwd[cwd] = workspace
            self._upsert_workspace(conn, workspace)
            conn.execute(
                """
                UPDATE events
                SET workspace_id = ?,
                    workspace_root = ?,
                    workspace_lexical_root = ?,
                    workspace_execution_cwd = ?,
                    workspace_status = ?,
                    workspace_source = ?
                WHERE event_id = ?
                """,
                (
                    workspace.workspace_id,
                    workspace.canonical_root,
                    workspace.lexical_root,
                    workspace.execution_cwd,
                    workspace.status,
                    workspace.discovered_by,
                    event_id,
                ),
            )
        conn.execute(
            """
            INSERT INTO analysis_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            (migration_key, "complete"),
        )

    def _upsert_workspace_for_event(
        self,
        conn: sqlite3.Connection,
        event: NormalizedEvent,
    ) -> None:
        self._upsert_workspace(
            conn,
            WorkspaceContext(
                workspace_id=event.workspace_id,
                canonical_root=event.workspace_root,
                lexical_root=event.workspace_lexical_root,
                execution_cwd=event.workspace_execution_cwd,
                status=event.workspace_status,
                discovered_by=event.workspace_source,
            ),
        )

    def _upsert_workspace(
        self,
        conn: sqlite3.Connection,
        workspace: WorkspaceContext,
    ) -> None:
        if workspace.workspace_id is None:
            return
        assert workspace.canonical_root is not None
        assert workspace.lexical_root is not None
        existing_id = conn.execute(
            "SELECT canonical_root FROM workspaces WHERE workspace_id = ?",
            (workspace.workspace_id,),
        ).fetchone()
        if existing_id is not None and existing_id[0] != workspace.canonical_root:
            raise ValueError("workspace id maps to a different canonical root")
        existing_root = conn.execute(
            "SELECT workspace_id FROM workspaces WHERE canonical_root = ?",
            (workspace.canonical_root,),
        ).fetchone()
        if existing_root is not None and existing_root[0] != workspace.workspace_id:
            raise ValueError("workspace root maps to a different workspace id")
        conn.execute(
            """
            INSERT INTO workspaces (
                workspace_id,
                canonical_root,
                lexical_root,
                discovered_by
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET
                lexical_root = excluded.lexical_root,
                discovered_by = excluded.discovered_by,
                last_seen_at = CURRENT_TIMESTAMP
            """,
            (
                workspace.workspace_id,
                workspace.canonical_root,
                workspace.lexical_root,
                workspace.discovered_by,
            ),
        )

    def _backfill_tool_operation_outcomes(self, conn: sqlite3.Connection) -> None:
        """旧DBの可変outcomeを、対応する最新Postへ保守的に移す。"""
        migration_key = "migration.tool_operation_outcomes.v1"
        if conn.execute(
            "SELECT 1 FROM analysis_state WHERE key = ?",
            (migration_key,),
        ).fetchone() is not None:
            return
        conn.execute(
            """
            INSERT OR IGNORE INTO tool_operation_outcomes (
                post_event_id,
                operation_id,
                session_id,
                tool_use_id,
                outcome,
                outcome_evidence
            )
            SELECT
                post.event_id,
                operation.operation_id,
                operation.session_id,
                operation.tool_use_id,
                operation.outcome,
                operation.outcome_evidence
            FROM tool_operations AS operation
            JOIN events AS post
              ON post.event_id = (
                  SELECT candidate.event_id
                  FROM events AS candidate
                  WHERE candidate.phase = 'post_tool_use'
                    AND candidate.session_id = operation.session_id
                    AND candidate.tool_use_id = operation.tool_use_id
                  ORDER BY candidate.sequence_no DESC, candidate.event_id DESC
                  LIMIT 1
              )
            WHERE operation.outcome IN ('succeeded', 'failed')
            """
        )
        conn.execute(
            "INSERT INTO analysis_state (key, value) VALUES (?, ?)",
            (migration_key, "complete"),
        )

    def _next_sequence_no(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM events"
        ).fetchone()
        return int(row[0])

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _connect_redaction_audit(self) -> sqlite3.Connection:
        timeout_seconds = REDACTION_AUDIT_BUSY_TIMEOUT_MS / 1000
        conn = sqlite3.connect(self.db_path, timeout=timeout_seconds)
        conn.execute(
            f"PRAGMA busy_timeout = {REDACTION_AUDIT_BUSY_TIMEOUT_MS}"
        )
        return conn


def _update_workspace_analysis_input_revision(
    digest: Any,
    label: str,
    rows: list[tuple[object, ...]],
) -> None:
    digest.update(label.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(len(rows)).encode("ascii"))
    digest.update(b"\n")
    for row in rows:
        digest.update(
            json.dumps(
                row,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        digest.update(b"\n")


def _sqlite_is_busy(exc: sqlite3.OperationalError) -> bool:
    error_code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(error_code, int):
        primary_code = error_code & 0xFF
        return primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
    message = str(exc).lower()
    return "locked" in message or "busy" in message


def _redaction_post_input_observation(
    event: NormalizedEvent,
    *,
    payload_bytes: int,
) -> tuple[str, str | None, PostRedactionInputObservation]:
    """Bind a redaction call scope to bounded, hash-only Post metadata."""
    scope_sha256 = _redaction_call_scope_sha256(event)
    if scope_sha256 is None:
        return (
            "not_applicable",
            None,
            PostRedactionInputObservation("not_applicable"),
        )

    if event.phase == "pre_tool_use":
        return (
            "pre",
            scope_sha256,
            PostRedactionInputObservation("not_applicable"),
        )
    if payload_bytes > REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES:
        return (
            "post",
            scope_sha256,
            PostRedactionInputObservation(
                "unobserved",
                observer_version=REDACTION_POST_INPUT_OBSERVER_VERSION,
                diagnostic_code="post_payload_bytes_exceeded",
            ),
        )
    observation = observe_mcp_post_input(
        tool_name=event.tool_name,
        tool_input=event.raw_payload.get("tool_input"),
    )
    return "post", scope_sha256, observation


def _redaction_call_scope_sha256(event: NormalizedEvent) -> str | None:
    if (
        event.phase not in {"pre_tool_use", "post_tool_use"}
        or event.workspace_status != "ready"
        or event.workspace_id is None
        or event.workspace_root is None
        or event.workspace_execution_cwd is None
        or event.session_id is None
        or event.tool_use_id is None
        or event.tool_name is None
        or not all(
            _bounded_audit_identifier(value)
            for value in (
                event.workspace_id,
                event.workspace_root,
                event.workspace_execution_cwd,
                event.session_id,
                event.tool_use_id,
                event.tool_name,
            )
        )
        or (
            event.turn_id is not None
            and not _bounded_audit_identifier(event.turn_id)
        )
        or (
            event.workspace_namespace_id is not None
            and not _bounded_audit_identifier(event.workspace_namespace_id)
        )
        or parse_mcp_tool_name(event.tool_name) is None
    ):
        return None
    scope_json = json.dumps(
        [
            "tooluseproxy:redaction-call-scope:v1",
            event.workspace_status,
            event.workspace_id,
            event.workspace_root,
            event.workspace_execution_cwd,
            event.workspace_namespace_id,
            event.session_id,
            event.turn_id,
            event.tool_use_id,
            event.tool_name,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(scope_json).hexdigest()


def _event_payload_metadata_sha256(
    *,
    event_id: str,
    payload_bytes: int,
    payload_sha256: str,
    sequence_no: int,
    redaction_event_kind: str,
    redaction_scope_sha256: str | None,
    post_input_observation: PostRedactionInputObservation,
) -> str:
    encoded = json.dumps(
        [
            "tooluseproxy:event-payload-metadata-integrity:v1",
            event_id,
            _EVENT_PAYLOAD_METADATA_VERSION,
            payload_bytes,
            payload_sha256,
            sequence_no,
            redaction_event_kind,
            redaction_scope_sha256,
            post_input_observation.status,
            post_input_observation.observer_version,
            post_input_observation.diagnostic_code,
            post_input_observation.profile_id,
            post_input_observation.profile_version,
            post_input_observation.profile_registry_version,
            post_input_observation.input_bytes,
            post_input_observation.input_sha256,
            post_input_observation.structure_sha256,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _event_payload_metadata_from_row(
    row: tuple[object, ...] | None,
) -> _EventPayloadMetadata | None:
    if row is None or len(row) != 17:
        return None
    (
        event_id,
        metadata_version,
        metadata_sha256,
        payload_bytes,
        payload_sha256,
        sequence_no,
        redaction_event_kind,
        redaction_scope_sha256,
        post_input_status,
        post_input_observer_version,
        post_input_diagnostic_code,
        post_profile_id,
        post_profile_version,
        post_profile_registry_version,
        post_input_bytes,
        post_input_sha256,
        post_structure_sha256,
    ) = row
    optional_text = (
        redaction_scope_sha256,
        post_input_observer_version,
        post_input_diagnostic_code,
        post_profile_id,
        post_profile_version,
        post_profile_registry_version,
        post_input_sha256,
        post_structure_sha256,
    )
    if (
        not isinstance(event_id, str)
        or not event_id
        or metadata_version != _EVENT_PAYLOAD_METADATA_VERSION
        or not isinstance(metadata_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(metadata_sha256) is None
        or type(payload_bytes) is not int
        or payload_bytes < 0
        or not isinstance(payload_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(payload_sha256) is None
        or type(sequence_no) is not int
        or sequence_no < 1
        or redaction_event_kind
        not in {"not_applicable", "pre", "post"}
        or post_input_status
        not in {"not_applicable", "captured", "unobserved"}
        or any(
            value is not None and not isinstance(value, str)
            for value in optional_text
        )
        or (
            post_input_bytes is not None
            and type(post_input_bytes) is not int
        )
    ):
        return None
    if redaction_event_kind == "not_applicable":
        if redaction_scope_sha256 is not None:
            return None
    elif (
        not isinstance(redaction_scope_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(redaction_scope_sha256) is None
    ):
        return None

    observation = PostRedactionInputObservation(
        status=post_input_status,
        observer_version=post_input_observer_version,
        diagnostic_code=post_input_diagnostic_code,
        profile_id=post_profile_id,
        profile_version=post_profile_version,
        profile_registry_version=post_profile_registry_version,
        input_bytes=post_input_bytes,
        input_sha256=post_input_sha256,
        structure_sha256=post_structure_sha256,
    )
    observation_values = (
        observation.observer_version,
        observation.diagnostic_code,
        observation.profile_id,
        observation.profile_version,
        observation.profile_registry_version,
        observation.input_bytes,
        observation.input_sha256,
        observation.structure_sha256,
    )
    if observation.status == "not_applicable":
        if redaction_event_kind == "post" or any(
            value is not None for value in observation_values
        ):
            return None
    elif observation.status == "unobserved":
        if (
            redaction_event_kind != "post"
            or observation.observer_version
            != REDACTION_POST_INPUT_OBSERVER_VERSION
            or observation.diagnostic_code
            not in REDACTION_POST_INPUT_DIAGNOSTIC_CODES
            or any(
                value is not None
                for value in (
                    observation.profile_id,
                    observation.profile_version,
                    observation.profile_registry_version,
                    observation.input_bytes,
                    observation.input_sha256,
                    observation.structure_sha256,
                )
            )
        ):
            return None
    elif (
        redaction_event_kind != "post"
        or payload_bytes > REDACTION_AUDIT_EVENT_PAYLOAD_MAX_BYTES
        or observation.observer_version
        != REDACTION_POST_INPUT_OBSERVER_VERSION
        or observation.diagnostic_code is not None
        or not _bounded_audit_identifier(observation.profile_id)
        or not _bounded_audit_identifier(observation.profile_version)
        or not _bounded_audit_identifier(
            observation.profile_registry_version
        )
        or type(observation.input_bytes) is not int
        or not 0
        <= observation.input_bytes
        <= DEFAULT_MCP_INPUT_LIMITS.max_input_bytes
        or not isinstance(observation.input_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(observation.input_sha256) is None
        or not isinstance(observation.structure_sha256, str)
        or _LOWER_SHA256_RE.fullmatch(observation.structure_sha256) is None
    ):
        return None

    expected_metadata_sha256 = _event_payload_metadata_sha256(
        event_id=event_id,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        sequence_no=sequence_no,
        redaction_event_kind=redaction_event_kind,
        redaction_scope_sha256=redaction_scope_sha256,
        post_input_observation=observation,
    )
    if metadata_sha256 != expected_metadata_sha256:
        return None
    return _EventPayloadMetadata(
        event_id=event_id,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        sequence_no=sequence_no,
        redaction_event_kind=redaction_event_kind,
        redaction_scope_sha256=redaction_scope_sha256,
        post_input_observation=observation,
    )


def _bounded_audit_identifier(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if len(value) > MCP_TOOL_NAME_MAX_BYTES:
        return False
    try:
        return len(value.encode("utf-8")) <= MCP_TOOL_NAME_MAX_BYTES
    except UnicodeEncodeError:
        return False


def _validate_event_workspace(event: NormalizedEvent) -> None:
    expected_event_id = make_event_id(
        event.phase,
        event.raw_payload,
        workspace_namespace_id=event.workspace_namespace_id,
    )
    if event.event_id != expected_event_id:
        raise ValueError("event id does not match payload and workspace identity")
    if not event.workspace_status:
        raise ValueError("workspace status is required")
    if not event.workspace_source:
        raise ValueError("workspace source is required")
    if event.workspace_source in {"configured_root", "registered_root"}:
        if event.workspace_namespace_id is None:
            raise ValueError("configured workspace namespace is required")
        if event.workspace_status == "ready":
            if event.workspace_namespace_id != event.workspace_id:
                raise ValueError("ready workspace namespace must match workspace id")
        elif not event.workspace_namespace_id.startswith(
            f"{WORKSPACE_CONFIGURED_NAMESPACE_VERSION}_"
        ):
            raise ValueError("unresolved configured workspace namespace is invalid")
    elif event.workspace_namespace_id is not None:
        raise ValueError("hook cwd workspace must not have a namespace salt")
    fields = (
        event.workspace_id,
        event.workspace_root,
        event.workspace_lexical_root,
        event.workspace_execution_cwd,
    )
    if event.workspace_status == "ready":
        if any(value is None for value in fields):
            raise ValueError("ready workspace event is missing identity fields")
        assert event.workspace_id is not None and event.workspace_root is not None
        if make_workspace_id(event.workspace_root) != event.workspace_id:
            raise ValueError("workspace id does not match canonical root")
        if event.workspace_source not in {
            "configured_root",
            "hook_cwd",
            "registered_root",
        }:
            raise ValueError("ready workspace event has an invalid source")
        assert event.workspace_execution_cwd is not None
        if not os.path.isabs(event.workspace_root) or not os.path.isabs(
            event.workspace_execution_cwd
        ):
            raise ValueError("workspace paths must be absolute")
        try:
            inside_workspace = (
                os.path.commonpath(
                    (event.workspace_root, event.workspace_execution_cwd)
                )
                == event.workspace_root
            )
        except ValueError:
            inside_workspace = False
        if not inside_workspace:
            raise ValueError("workspace execution cwd is outside canonical root")
        configured_root = (
            event.workspace_lexical_root
            if event.workspace_source in {"configured_root", "registered_root"}
            else None
        )
        expected_workspace = resolve_workspace(
            event.cwd,
            configured_root,
            discovered_by=event.workspace_source,
        )
        stored_workspace = WorkspaceContext(
            workspace_id=event.workspace_id,
            canonical_root=event.workspace_root,
            lexical_root=event.workspace_lexical_root,
            execution_cwd=event.workspace_execution_cwd,
            status=event.workspace_status,
            discovered_by=event.workspace_source,
        )
        if expected_workspace != stored_workspace:
            raise ValueError("workspace context does not match current filesystem state")
        return
    if any(value is not None for value in fields):
        raise ValueError("unresolved workspace event must not carry identity fields")


def _enable_wal(conn: sqlite3.Connection) -> None:
    deadline = time.monotonic() + 5.0
    while True:
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).casefold() or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _validate_workspace_source_catalog(
    workspace_id: str,
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
) -> None:
    if not workspace_id:
        raise ValueError("workspace id is required for source catalog")
    source_ids: set[str] = set()
    source_keys: set[str] = set()
    for source in sources:
        _validate_model_source_selector(source)
        if source.workspace_id != workspace_id or not source.source_key:
            raise ValueError("protected source workspace does not match catalog")
        if source.source_id != make_scoped_source_id(
            workspace_id,
            source.source_key,
        ):
            raise ValueError("protected source id does not match workspace namespace")
        if source.source_id in source_ids or source.source_key in source_keys:
            raise ValueError("duplicate protected source in workspace catalog")
        source_ids.add(source.source_id)
        source_keys.add(source.source_key)

    chunk_ids: set[str] = set()
    source_ordinals: set[tuple[str, int]] = set()
    for chunk in chunks:
        if chunk.workspace_id != workspace_id:
            raise ValueError("source chunk workspace does not match catalog")
        if chunk.source_id not in source_ids:
            raise ValueError("source chunk does not belong to workspace source")
        if chunk.chunk_id != make_source_chunk_id(
            chunk.source_id,
            chunk.ordinal,
            chunk.text,
        ):
            raise ValueError("source chunk id does not match source content")
        if chunk.text_hash != hashlib.sha256(chunk.text.encode("utf-8")).hexdigest():
            raise ValueError("source chunk hash does not match source content")
        if chunk.chunk_id in chunk_ids:
            raise ValueError("duplicate source chunk in workspace catalog")
        source_ordinal = (chunk.source_id, chunk.ordinal)
        if source_ordinal in source_ordinals:
            raise ValueError("duplicate source chunk ordinal in workspace catalog")
        chunk_ids.add(chunk.chunk_id)
        source_ordinals.add(source_ordinal)


def _validate_legacy_source_catalog(
    sources: list[ProtectedSource],
    chunks: list[SourceChunk],
) -> None:
    source_ids: set[str] = set()
    for source in sources:
        _validate_model_source_selector(source)
        if source.workspace_id is not None or source.source_key is not None:
            raise ValueError("legacy source catalog cannot contain workspace metadata")
        if source.source_id in source_ids:
            raise ValueError("duplicate legacy protected source")
        source_ids.add(source.source_id)
    chunk_ids: set[str] = set()
    source_ordinals: set[tuple[str, int]] = set()
    for chunk in chunks:
        if chunk.workspace_id is not None:
            raise ValueError("legacy source chunk cannot contain workspace metadata")
        if chunk.chunk_id in chunk_ids:
            raise ValueError("duplicate legacy source chunk")
        source_ordinal = (chunk.source_id, chunk.ordinal)
        if source_ordinal in source_ordinals:
            raise ValueError("duplicate legacy source chunk ordinal")
        chunk_ids.add(chunk.chunk_id)
        source_ordinals.add(source_ordinal)


def _validate_model_source_selector(source: ProtectedSource) -> None:
    canonical = parse_protected_source_selector(
        protected_source_selector_payload(source.selector),
        source_path=source.path,
        source_type=source.source_type,
    )
    if canonical != source.selector:
        raise ValueError("protected source selector is not canonical")


def _validate_node_workspace_owners(
    nodes: list[tuple[str, str | None]],
) -> None:
    owners: dict[str, str | None] = {}
    for node_id, workspace_id in nodes:
        if node_id in owners and owners[node_id] != workspace_id:
            raise ValueError("derived node id has conflicting workspace owners")
        owners[node_id] = workspace_id


def _validate_assignment_run_ids(
    assignments: list[LineageAssignment],
    analysis_run_id: str,
) -> None:
    if any(
        assignment.analysis_run_id != analysis_run_id
        for assignment in assignments
    ):
        raise ValueError("lineage assignment does not match analysis run")


def _stored_derived_workspace_id(workspace_id: str | None) -> str:
    return workspace_id or LEGACY_DERIVED_WORKSPACE_ID


def _model_derived_workspace_id(workspace_id: str) -> str | None:
    if workspace_id == LEGACY_DERIVED_WORKSPACE_ID:
        return None
    return workspace_id


def _workspace_context_from_registry_row(row: tuple) -> WorkspaceContext:
    return WorkspaceContext(
        workspace_id=row[0],
        canonical_root=row[1],
        lexical_root=row[2],
        execution_cwd=row[1],
        status="ready",
        discovered_by=row[3],
    )


def _protected_source_from_row(row: tuple) -> ProtectedSource:
    return ProtectedSource(
        source_id=row[0],
        path=row[1],
        source_type=row[2],
        sensitivity=row[3],
        policy_tags=tuple(json.loads(row[4])),
        workspace_id=row[5],
        source_key=row[6],
        selector=parse_protected_source_selector(
            json.loads(row[7]),
            source_path=row[1],
            source_type=row[2],
        ),
    )


def _source_chunk_from_row(row: tuple) -> SourceChunk:
    return SourceChunk(
        chunk_id=row[0],
        source_id=row[1],
        ordinal=row[2],
        text=row[3],
        normalized_text=row[4],
        text_hash=row[5],
        shingle_fingerprint=row[6],
        token_count=row[7],
        workspace_id=row[8],
    )


def _flow_edge_values(edge: FlowEdge) -> tuple[object, ...]:
    return (
        edge.edge_id,
        edge.src_node_kind,
        edge.src_node_id,
        edge.dst_node_kind,
        edge.dst_node_id,
        edge.relation,
        edge.evidence_level,
        edge.method,
        edge.score,
        edge.reason,
    )


def _flow_edge_from_row(row: tuple) -> FlowEdge:
    return FlowEdge(
        edge_id=row[0],
        src_node_kind=row[1],
        src_node_id=row[2],
        dst_node_kind=row[3],
        dst_node_id=row[4],
        relation=row[5],
        evidence_level=row[6],
        method=row[7],
        score=row[8],
        reason=row[9],
    )


def _resource_values(resource: ResourceVersion) -> tuple[object, ...]:
    return (
        resource.node_id,
        _stored_derived_workspace_id(resource.workspace_id),
        resource.path,
        resource.content_hash,
        resource.sequence_no,
        resource.session_id,
        resource.origin_tool_use_id,
        resource.operation_id,
        resource.operation_index,
        resource.snapshot_id,
        resource.resource_state,
    )


def _tool_operation_values(operation: ToolOperation) -> tuple[object, ...]:
    return (
        operation.operation_id,
        operation.event_id,
        operation.artifact_id,
        operation.parent_fragment_id,
        operation.session_id,
        operation.tool_use_id,
        operation.tool_name,
        operation.adapter,
        operation.operation_index,
        operation.operation_kind,
        operation.source_path,
        operation.target_path,
        operation.segment_index,
        operation.connector,
        operation.content_fragment_id,
        operation.outcome,
        operation.outcome_evidence,
    )


def _normalized_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.casefold()).strip("_")
    return normalized or None


def _resource_snapshot_values(snapshot: ResourceSnapshot) -> tuple[object, ...]:
    return (
        snapshot.snapshot_id,
        snapshot.post_event_id,
        snapshot.operation_id,
        snapshot.session_id,
        snapshot.tool_use_id,
        snapshot.path_role,
        snapshot.requested_path,
        snapshot.workspace_root,
        snapshot.lexical_path,
        snapshot.resource_state,
        snapshot.capture_status,
        snapshot.file_kind,
        snapshot.byte_size,
        snapshot.captured_bytes,
        snapshot.content_sha256,
        snapshot.encoding,
        snapshot.body_text,
        snapshot.error_code,
        snapshot.duration_ms,
    )


def _sink_values(sink: SinkCandidate) -> tuple[object, ...]:
    return (
        sink.node_id,
        _stored_derived_workspace_id(sink.workspace_id),
        sink.sink_type,
        sink.label,
        sink.tool_name,
        sink.tool_use_id,
        sink.session_id,
        sink.sequence_no,
        json.dumps(sink.metadata, ensure_ascii=False, sort_keys=True),
    )


def _load_bounded_source_chunk_evidence(
    conn: sqlite3.Connection,
    workspace_id: str,
    chunk_ids: tuple[str, ...],
    *,
    max_ids: int,
    max_bytes_per_chunk: int,
    max_bytes_total: int,
) -> list[SourceChunkEvidence]:
    if len(chunk_ids) > max_ids:
        raise ValueError("source chunk lookup limit exceeded")
    if not chunk_ids:
        return []
    placeholders = ",".join("?" for _ in chunk_ids)
    sized_rows = conn.execute(
        f"""
        SELECT
            chunk.chunk_id,
            length(CAST(chunk.text AS BLOB)),
            length(chunk.text_hash)
        FROM source_chunks AS chunk
        JOIN protected_sources AS source
          ON source.source_id = chunk.source_id
         AND source.workspace_id = chunk.workspace_id
        WHERE chunk.workspace_id = ?
          AND source.workspace_id = ?
          AND chunk.chunk_id IN ({placeholders})
        ORDER BY chunk.chunk_id
        """,
        (workspace_id, workspace_id, *chunk_ids),
    ).fetchall()
    byte_sizes = tuple(int(row[1]) for row in sized_rows)
    if any(row[2] != 64 for row in sized_rows):
        raise ValueError("source chunk hash metadata is invalid")
    if any(size > max_bytes_per_chunk for size in byte_sizes):
        raise ValueError("source chunk byte limit exceeded")
    if sum(byte_sizes) > max_bytes_total:
        raise ValueError("source chunk total byte limit exceeded")
    rows = conn.execute(
        f"""
        SELECT
            chunk.chunk_id,
            chunk.text,
            chunk.text_hash,
            chunk.workspace_id
        FROM source_chunks AS chunk
        JOIN protected_sources AS source
          ON source.source_id = chunk.source_id
         AND source.workspace_id = chunk.workspace_id
        WHERE chunk.workspace_id = ?
          AND source.workspace_id = ?
          AND chunk.chunk_id IN ({placeholders})
        ORDER BY chunk.chunk_id
        """,
        (workspace_id, workspace_id, *chunk_ids),
    ).fetchall()
    return [SourceChunkEvidence(*row) for row in rows]


def _redaction_plan_values(plan: StoredRedactionPlan) -> tuple[object, ...]:
    return (
        plan.plan_id,
        plan.analysis_run_id,
        plan.pre_event_id,
        plan.workspace_id,
        plan.session_id,
        plan.tool_use_id,
        plan.tool_name,
        plan.adapter,
        plan.profile_id,
        plan.profile_version,
        plan.profile_registry_version,
        plan.mode,
        plan.status,
        plan.planner_version,
        plan.original_input_sha256,
        plan.rewritten_input_sha256,
        plan.structure_sha256_before,
        plan.structure_sha256_after,
        plan.critical_finding_count,
        plan.replacement_count,
        plan.rejection_code,
        plan.post_event_id,
        plan.rendered_at,
        plan.confirmed_at,
    )


def _redaction_target_values(
    target: StoredRedactionTarget,
) -> tuple[object, ...]:
    return (
        target.plan_id,
        target.ordinal,
        target.finding_id,
        target.decision_id,
        target.source_node_kind,
        target.source_node_id,
        target.sink_node_id,
        target.json_pointer,
        target.original_value_sha256,
        target.replacement_profile,
    )


def _redaction_plan_id_for_mode(
    plan: StoredRedactionPlan,
    mode: str,
) -> str:
    return hashlib.sha256(
        "\0".join(
            (
                plan.workspace_id,
                plan.pre_event_id,
                plan.analysis_run_id,
                plan.planner_version,
                plan.profile_version,
                mode,
            )
        ).encode("utf-8")
    ).hexdigest()


def _make_redaction_decision_link(
    *,
    enforce_plan_id: str,
    preview_plan_id: str,
    target: StoredRedactionTarget,
) -> StoredRedactionDecisionLink:
    derived = derive_redact_decision(
        finding_id=target.finding_id,
        source_block_decision_id=target.decision_id,
    )
    metadata_sha256 = _redaction_decision_link_metadata_sha256(
        enforce_plan_id=enforce_plan_id,
        target_ordinal=target.ordinal,
        preview_plan_id=preview_plan_id,
        finding_id=target.finding_id,
        source_block_decision_id=target.decision_id,
        derived_redact_decision_id=derived.derived_redact_decision_id,
        derivation_version=derived.derivation_version,
    )
    return StoredRedactionDecisionLink(
        enforce_plan_id=enforce_plan_id,
        target_ordinal=target.ordinal,
        preview_plan_id=preview_plan_id,
        finding_id=target.finding_id,
        source_block_decision_id=target.decision_id,
        derived_redact_decision_id=derived.derived_redact_decision_id,
        derivation_version=derived.derivation_version,
        metadata_sha256=metadata_sha256,
    )


def _redaction_decision_link_metadata_sha256(
    *,
    enforce_plan_id: str,
    target_ordinal: int,
    preview_plan_id: str,
    finding_id: str,
    source_block_decision_id: str,
    derived_redact_decision_id: str,
    derivation_version: str,
) -> str:
    encoded = json.dumps(
        [
            "tooluseproxy:redaction-decision-link-integrity:v1",
            enforce_plan_id,
            target_ordinal,
            preview_plan_id,
            finding_id,
            source_block_decision_id,
            derived_redact_decision_id,
            derivation_version,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _redaction_decision_link_values(
    link: StoredRedactionDecisionLink,
) -> tuple[object, ...]:
    return (
        link.enforce_plan_id,
        link.target_ordinal,
        link.preview_plan_id,
        link.finding_id,
        link.source_block_decision_id,
        link.derived_redact_decision_id,
        link.derivation_version,
        link.metadata_sha256,
    )


def _stored_redaction_decision_link_from_row(
    row: tuple[object, ...],
) -> StoredRedactionDecisionLink:
    if len(row) != 9:
        raise ValueError("redaction decision link row is invalid")
    link = StoredRedactionDecisionLink(
        enforce_plan_id=row[0],
        target_ordinal=row[1],
        preview_plan_id=row[2],
        finding_id=row[3],
        source_block_decision_id=row[4],
        derived_redact_decision_id=row[5],
        derivation_version=row[6],
        metadata_sha256=row[7],
        created_at=row[8],
    )
    _validate_stored_redaction_decision_link(link)
    return link


def _validate_stored_redaction_decision_link(
    link: StoredRedactionDecisionLink,
) -> None:
    hashes = (
        link.enforce_plan_id,
        link.preview_plan_id,
        link.finding_id,
        link.source_block_decision_id,
        link.derived_redact_decision_id,
        link.metadata_sha256,
    )
    if any(
        not isinstance(value, str)
        or _LOWER_SHA256_RE.fullmatch(value) is None
        for value in hashes
    ):
        raise ValueError("redaction decision link hashes are invalid")
    if (
        link.enforce_plan_id == link.preview_plan_id
        or type(link.target_ordinal) is not int
        or not 0
        <= link.target_ordinal
        < REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
        or link.derivation_version
        != REDACTION_DECISION_DERIVATION_VERSION
        or (
            link.created_at is not None
            and (
                not isinstance(link.created_at, str)
                or not link.created_at
            )
        )
    ):
        raise ValueError("redaction decision link fields are invalid")
    derived = derive_redact_decision(
        finding_id=link.finding_id,
        source_block_decision_id=link.source_block_decision_id,
    )
    if link.derived_redact_decision_id != derived.derived_redact_decision_id:
        raise ValueError("redaction decision derivation is invalid")
    expected_metadata_sha256 = _redaction_decision_link_metadata_sha256(
        enforce_plan_id=link.enforce_plan_id,
        target_ordinal=link.target_ordinal,
        preview_plan_id=link.preview_plan_id,
        finding_id=link.finding_id,
        source_block_decision_id=link.source_block_decision_id,
        derived_redact_decision_id=link.derived_redact_decision_id,
        derivation_version=link.derivation_version,
    )
    if link.metadata_sha256 != expected_metadata_sha256:
        raise ValueError("redaction decision link integrity mismatch")


def _validate_prepared_redaction_enforcement(
    *,
    preview: StoredRedactionPlan,
    enforce: StoredRedactionPlan,
    links: tuple[StoredRedactionDecisionLink, ...],
) -> None:
    if (
        preview.mode != "preview"
        or preview.status != "eligible"
        or enforce.mode != "enforce"
        or enforce.status != "eligible"
        or enforce.plan_id != _redaction_plan_id_for_mode(preview, "enforce")
        or enforce.analysis_run_id != preview.analysis_run_id
        or enforce.pre_event_id != preview.pre_event_id
        or enforce.workspace_id != preview.workspace_id
        or enforce.session_id != preview.session_id
        or enforce.tool_use_id != preview.tool_use_id
        or enforce.tool_name != preview.tool_name
        or enforce.adapter != preview.adapter
        or enforce.profile_id != preview.profile_id
        or enforce.profile_version != preview.profile_version
        or enforce.profile_registry_version != preview.profile_registry_version
        or enforce.planner_version != preview.planner_version
        or enforce.original_input_sha256 != preview.original_input_sha256
        or enforce.rewritten_input_sha256 != preview.rewritten_input_sha256
        or enforce.structure_sha256_before != preview.structure_sha256_before
        or enforce.structure_sha256_after != preview.structure_sha256_after
        or enforce.critical_finding_count != preview.critical_finding_count
        or enforce.replacement_count != preview.replacement_count
        or enforce.rejection_code is not None
        or enforce.post_event_id is not None
        or enforce.rendered_at is not None
        or enforce.confirmed_at is not None
        or len(enforce.targets) != enforce.critical_finding_count
        or len(links) != enforce.critical_finding_count
    ):
        raise ValueError("redaction enforcement plan does not clone its preview")

    expected_ordinals = tuple(range(enforce.critical_finding_count))
    if (
        tuple(target.ordinal for target in enforce.targets) != expected_ordinals
        or tuple(link.target_ordinal for link in links) != expected_ordinals
    ):
        raise ValueError("redaction enforcement ordinals are incomplete")
    if (
        len({link.finding_id for link in links}) != len(links)
        or len({link.source_block_decision_id for link in links}) != len(links)
        or len({link.derived_redact_decision_id for link in links}) != len(links)
    ):
        raise ValueError("redaction enforcement decisions are incomplete")

    for preview_target, enforce_target, link in zip(
        preview.targets,
        enforce.targets,
        links,
    ):
        if (
            enforce_target.plan_id != enforce.plan_id
            or preview_target.plan_id != preview.plan_id
            or _redaction_target_values(enforce_target)[1:]
            != _redaction_target_values(preview_target)[1:]
            or link.enforce_plan_id != enforce.plan_id
            or link.preview_plan_id != preview.plan_id
            or link.target_ordinal != enforce_target.ordinal
            or link.finding_id != enforce_target.finding_id
            or link.source_block_decision_id != enforce_target.decision_id
        ):
            raise ValueError("redaction enforcement decision linkage mismatch")
        _validate_stored_redaction_decision_link(link)


def _prepared_redaction_enforcement_matches(
    *,
    expected: StoredRedactionPlan,
    actual: StoredRedactionPlan,
    expected_links: tuple[StoredRedactionDecisionLink, ...],
    actual_links: tuple[StoredRedactionDecisionLink, ...],
) -> bool:
    return (
        actual.created_at is not None
        and _redaction_plan_values(actual) == _redaction_plan_values(expected)
        and tuple(
            _redaction_target_values(target) for target in actual.targets
        )
        == tuple(_redaction_target_values(target) for target in expected.targets)
        and tuple(
            _redaction_decision_link_values(link) for link in actual_links
        )
        == tuple(
            _redaction_decision_link_values(link) for link in expected_links
        )
    )


def _stored_redaction_target_from_row(
    row: tuple[object, ...],
) -> StoredRedactionTarget:
    if len(row) != 10:
        raise ValueError("redaction target row is invalid")
    return StoredRedactionTarget(
        plan_id=row[0],
        ordinal=row[1],
        finding_id=row[2],
        decision_id=row[3],
        source_node_kind=row[4],
        source_node_id=row[5],
        sink_node_id=row[6],
        json_pointer=row[7],
        original_value_sha256=row[8],
        replacement_profile=row[9],
    )


def _validate_redaction_confirmation_decision_links(
    *,
    enforce_plan_id: str,
    preview_plan_id: str,
    analysis_run_id: str,
    critical_finding_count: int,
    enforce_target_rows: list[tuple] | tuple[tuple, ...],
    preview_target_rows: list[tuple] | tuple[tuple, ...],
    decision_link_rows: list[tuple] | tuple[tuple, ...],
) -> None:
    if (
        type(critical_finding_count) is not int
        or not 0
        < critical_finding_count
        <= REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
        or len(enforce_target_rows) != critical_finding_count
        or len(preview_target_rows) != critical_finding_count
        or len(decision_link_rows) != critical_finding_count
    ):
        raise ValueError("rendered redaction decision linkage is incomplete")

    enforce_targets = tuple(
        _stored_redaction_target_from_row(row) for row in enforce_target_rows
    )
    preview_targets = tuple(
        _stored_redaction_target_from_row(row) for row in preview_target_rows
    )
    links = tuple(
        _stored_redaction_decision_link_from_row(row)
        for row in decision_link_rows
    )
    expected_ordinals = tuple(range(critical_finding_count))
    if (
        tuple(target.ordinal for target in enforce_targets) != expected_ordinals
        or tuple(target.ordinal for target in preview_targets)
        != expected_ordinals
        or tuple(link.target_ordinal for link in links) != expected_ordinals
        or len({link.finding_id for link in links}) != len(links)
        or len({link.source_block_decision_id for link in links}) != len(links)
        or len({link.derived_redact_decision_id for link in links})
        != len(links)
    ):
        raise ValueError("rendered redaction decision linkage is ambiguous")

    for enforce_target, preview_target, link in zip(
        enforce_targets,
        preview_targets,
        links,
    ):
        expected_finding_id = hashlib.sha256(
            "\0".join(
                (
                    analysis_run_id,
                    enforce_target.source_node_kind,
                    enforce_target.source_node_id,
                    enforce_target.sink_node_id,
                )
            ).encode("utf-8")
        ).hexdigest()
        expected_link = _make_redaction_decision_link(
            enforce_plan_id=enforce_plan_id,
            preview_plan_id=preview_plan_id,
            target=enforce_target,
        )
        if (
            enforce_target.plan_id != enforce_plan_id
            or preview_target.plan_id != preview_plan_id
            or _redaction_target_values(enforce_target)[1:]
            != _redaction_target_values(preview_target)[1:]
            or enforce_target.source_node_kind != "source_chunk"
            or enforce_target.finding_id != expected_finding_id
            or _redaction_decision_link_values(link)
            != _redaction_decision_link_values(expected_link)
        ):
            raise ValueError("rendered redaction decision linkage is invalid")


def _redaction_preview_matches_stored(
    preview: RedactionPreviewPlan,
    stored: StoredRedactionPlan,
) -> bool:
    expected_plan_values = (
        preview.plan_id,
        preview.analysis_run_id,
        preview.pre_event_id,
        preview.workspace_id,
        preview.session_id,
        preview.tool_use_id,
        preview.tool_name,
        preview.adapter,
        preview.profile_id,
        preview.profile_version,
        preview.profile_registry_version,
        preview.mode,
        preview.status,
        preview.planner_version,
        preview.original_input_sha256,
        preview.rewritten_input_sha256,
        preview.structure_sha256_before,
        preview.structure_sha256_after,
        preview.critical_finding_count,
        preview.replacement_count,
        preview.rejection_code,
        None,
        None,
        None,
    )
    expected_target_values = tuple(
        (
            preview.plan_id,
            target.ordinal,
            target.finding_id,
            target.decision_id,
            target.source_node_kind,
            target.source_node_id,
            target.sink_node_id,
            target.json_pointer,
            target.original_value_sha256,
            target.replacement_profile,
        )
        for target in preview.targets
    )
    return (
        _redaction_plan_values(stored) == expected_plan_values
        and tuple(_redaction_target_values(target) for target in stored.targets)
        == expected_target_values
    )


def _stored_redaction_plan_from_rows(
    row: tuple,
    target_rows: list[tuple] | tuple[tuple, ...],
) -> StoredRedactionPlan:
    targets = tuple(
        StoredRedactionTarget(
            plan_id=target[0],
            ordinal=target[1],
            finding_id=target[2],
            decision_id=target[3],
            source_node_kind=target[4],
            source_node_id=target[5],
            sink_node_id=target[6],
            json_pointer=target[7],
            original_value_sha256=target[8],
            replacement_profile=target[9],
        )
        for target in target_rows
    )
    return StoredRedactionPlan(
        plan_id=row[0],
        analysis_run_id=row[1],
        pre_event_id=row[2],
        workspace_id=row[3],
        session_id=row[4],
        tool_use_id=row[5],
        tool_name=row[6],
        adapter=row[7],
        profile_id=row[8],
        profile_version=row[9],
        profile_registry_version=row[10],
        mode=row[11],
        status=row[12],
        planner_version=row[13],
        original_input_sha256=row[14],
        rewritten_input_sha256=row[15],
        structure_sha256_before=row[16],
        structure_sha256_after=row[17],
        critical_finding_count=row[18],
        replacement_count=row[19],
        rejection_code=row[20],
        post_event_id=row[21],
        targets=targets,
        created_at=row[22],
        rendered_at=row[23],
        confirmed_at=row[24],
    )


def _validate_stored_redaction_plan(plan: StoredRedactionPlan) -> None:
    required_strings = (
        plan.plan_id,
        plan.analysis_run_id,
        plan.pre_event_id,
        plan.workspace_id,
        plan.session_id,
        plan.tool_use_id,
        plan.tool_name,
        plan.adapter,
        plan.profile_id,
        plan.profile_version,
        plan.profile_registry_version,
        plan.mode,
        plan.status,
        plan.planner_version,
    )
    if any(not isinstance(value, str) or not value for value in required_strings):
        raise ValueError("redaction plan identifiers must be non-empty strings")
    try:
        identifiers_are_bounded = all(
            len(value.encode("utf-8")) <= REDACTION_AUDIT_MAX_IDENTIFIER_BYTES
            for value in required_strings
        )
    except UnicodeEncodeError as exc:
        raise ValueError("redaction plan identifiers must be valid UTF-8") from exc
    if not identifiers_are_bounded:
        raise ValueError("redaction plan identifier byte limit exceeded")
    if not _LOWER_SHA256_RE.fullmatch(plan.plan_id):
        raise ValueError("redaction plan id must be a lowercase SHA-256")
    expected_plan_id = hashlib.sha256(
        "\0".join(
            (
                plan.workspace_id,
                plan.pre_event_id,
                plan.analysis_run_id,
                plan.planner_version,
                plan.profile_version,
                plan.mode,
            )
        ).encode("utf-8")
    ).hexdigest()
    if plan.plan_id != expected_plan_id:
        raise ValueError("redaction plan id does not match its scope")
    if plan.adapter != "mcp" or plan.mode != "preview":
        raise ValueError("redaction audit only accepts MCP preview plans")
    if plan.planner_version != REDACTION_PREVIEW_PLANNER_VERSION:
        raise ValueError("redaction preview planner version is invalid")
    if plan.status not in {"eligible", "rejected"}:
        raise ValueError("redaction preview status is invalid")
    if (
        type(plan.critical_finding_count) is not int
        or plan.critical_finding_count <= 0
        or plan.critical_finding_count
        > REDACTION_PREVIEW_MAX_CRITICAL_FINDINGS
        or type(plan.replacement_count) is not int
        or plan.replacement_count < 0
    ):
        raise ValueError("redaction preview counts are invalid")
    if not isinstance(plan.targets, tuple):
        raise ValueError("redaction preview targets must be a tuple")
    if len(plan.targets) > 32:
        raise ValueError("redaction preview target limit exceeded")
    if plan.post_event_id is not None:
        raise ValueError("preview plan must not claim a PostToolUse event")
    if plan.rendered_at is not None or plan.confirmed_at is not None:
        raise ValueError("preview plan must not claim rendered or confirmed state")
    if plan.created_at is not None and (
        not isinstance(plan.created_at, str) or not plan.created_at
    ):
        raise ValueError("redaction preview creation time is invalid")

    hashes = (
        plan.original_input_sha256,
        plan.rewritten_input_sha256,
        plan.structure_sha256_before,
        plan.structure_sha256_after,
    )
    if any(
        value is not None
        and (not isinstance(value, str) or not _LOWER_SHA256_RE.fullmatch(value))
        for value in hashes
    ):
        raise ValueError("redaction preview hashes must be lowercase SHA-256")
    if (plan.original_input_sha256 is None) != (
        plan.structure_sha256_before is None
    ):
        raise ValueError("redaction preview input and structure hashes must align")

    expected_ordinals = tuple(range(len(plan.targets)))
    if tuple(target.ordinal for target in plan.targets) != expected_ordinals:
        raise ValueError("redaction target ordinals must be contiguous")
    if len({target.finding_id for target in plan.targets}) != len(plan.targets):
        raise ValueError("redaction target finding ids must be unique")
    for target in plan.targets:
        if target.plan_id != plan.plan_id:
            raise ValueError("redaction target belongs to another plan")
        if target.source_node_kind != "source_chunk":
            raise ValueError("redaction target source kind is unsupported")
        target_strings = (
            target.finding_id,
            target.decision_id,
            target.source_node_id,
            target.sink_node_id,
            target.json_pointer,
            target.original_value_sha256,
            target.replacement_profile,
        )
        if any(
            not isinstance(value, str) or not value for value in target_strings
        ):
            raise ValueError("redaction target fields must be non-empty strings")
        try:
            target_fields_are_bounded = all(
                len(value.encode("utf-8"))
                <= REDACTION_AUDIT_MAX_IDENTIFIER_BYTES
                for value in target_strings
            )
        except UnicodeEncodeError as exc:
            raise ValueError("redaction target fields must be valid UTF-8") from exc
        if not target_fields_are_bounded:
            raise ValueError("redaction target field byte limit exceeded")
        if not target.json_pointer.startswith("/"):
            raise ValueError("redaction target must use an absolute JSON pointer")
        if target.replacement_profile != REDACTION_REPLACEMENT_PROFILE:
            raise ValueError("redaction target replacement profile is invalid")
        for value in (
            target.finding_id,
            target.decision_id,
            target.original_value_sha256,
        ):
            if not _LOWER_SHA256_RE.fullmatch(value):
                raise ValueError("redaction target hashes must be lowercase SHA-256")
        expected_finding_id = hashlib.sha256(
            "\0".join(
                (
                    plan.analysis_run_id,
                    target.source_node_kind,
                    target.source_node_id,
                    target.sink_node_id,
                )
            ).encode("utf-8")
        ).hexdigest()
        expected_decision_id = hashlib.sha256(
            "\0".join((expected_finding_id, "block", "PreToolUse")).encode(
                "utf-8"
            )
        ).hexdigest()
        if (
            target.finding_id != expected_finding_id
            or target.decision_id != expected_decision_id
        ):
            raise ValueError("redaction target ids do not match plan lineage")

    if plan.status == "eligible":
        if (
            any(value is None for value in hashes)
            or plan.structure_sha256_before != plan.structure_sha256_after
            or plan.original_input_sha256 == plan.rewritten_input_sha256
            or plan.rejection_code is not None
            or len(plan.targets) != plan.critical_finding_count
            or plan.replacement_count
            != len({target.json_pointer for target in plan.targets})
            or plan.replacement_count <= 0
        ):
            raise ValueError("eligible redaction preview invariants are invalid")
        return

    if (
        plan.targets
        or plan.replacement_count != 0
        or plan.rewritten_input_sha256 is not None
        or plan.structure_sha256_after is not None
        or not isinstance(plan.rejection_code, str)
        or plan.rejection_code not in REDACTION_PREVIEW_REJECTION_CODES
    ):
        raise ValueError("rejected redaction preview invariants are invalid")


def _validate_sqlite_utc_timestamp(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("redaction cleanup cutoff must be a UTC timestamp")
    try:
        parsed = time.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ValueError(
            "redaction cleanup cutoff must use YYYY-MM-DD HH:MM:SS UTC"
        ) from exc
    if time.strftime("%Y-%m-%d %H:%M:%S", parsed) != value:
        raise ValueError("redaction cleanup cutoff is not canonical")


def _stored_policy_decision_from_row(row: tuple) -> StoredPolicyDecision:
    return StoredPolicyDecision(
        decision_id=row[0],
        finding_id=row[1],
        analysis_run_id=row[2],
        hook_event=row[3],
        action=row[4],
        severity=row[5],
        sink_type=row[6],
        source_node_kind=row[7],
        source_node_id=row[8],
        sink_node_id=row[9],
        path_score=row[10],
        reason=row[11],
        user_message=row[12],
        technical_summary=row[13],
        trace_command=row[14],
        path_summary=tuple(json.loads(row[15])),
        created_at=row[16],
    )
