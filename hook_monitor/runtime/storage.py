from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import replace
from pathlib import Path

from hook_monitor.runtime.ids import make_event_id, make_source_chunk_id

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
    ResourceVersion,
    ResourceSnapshot,
    RuntimeAnalysisScope,
    SinkCandidate,
    SourceChunk,
    StoredPolicyDecision,
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
    resolve_protected_source_path,
)


DEFAULT_DB_PATH = Path(".tooluseproxy/events.db")
LEGACY_DERIVED_WORKSPACE_ID = "legacy_unscoped"


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

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
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._ensure_column(conn, "protected_sources", "workspace_id", "TEXT")
            self._ensure_column(conn, "protected_sources", "source_key", "TEXT")
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
                    json.dumps(event.raw_payload, ensure_ascii=False, sort_keys=True),
                    sequence_no,
                ),
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
                policy_tags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
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

    def complete_analysis_run(self, analysis_run_id: str) -> None:
        with self._connect() as conn:
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

        with self._connect() as conn:
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
                               policy_tags_json, workspace_id, source_key
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
                [
                    (workspace_id, *_flow_edge_values(edge))
                    for edge in edges
                ],
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
            self._validate_registered_workspace(conn, workspace_id)
            self._reject_cross_workspace_node_collisions(
                conn,
                "resource_versions",
                [(node_id, workspace_id) for node_id, _ in nodes],
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
            self._validate_registered_workspace(conn, workspace_id)
            self._reject_cross_workspace_node_collisions(
                conn,
                "sink_candidates",
                [(node_id, workspace_id) for node_id, _ in nodes],
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
        with self._connect() as conn:
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
                    source_key
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
                    source_key
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
        if not rows:
            return
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._validate_runtime_scope_owner(conn, workspace_id, session_id)
            conn.executemany(
                """
                INSERT OR IGNORE INTO fragment_shingles (
                    workspace_id, session_id, fragment_id, sequence_no, shingle
                ) VALUES (?, ?, ?, ?, ?)
                """,
                rows,
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
                    SELECT DISTINCT f.fragment_id
                    FROM artifact_fragments AS f
                    JOIN artifacts AS a ON a.artifact_id = f.artifact_id
                    JOIN events AS e ON e.event_id = a.event_id
                    JOIN fragment_shingles AS i
                      ON i.workspace_id = e.workspace_id
                     AND i.session_id = e.session_id
                     AND i.fragment_id = f.fragment_id
                    WHERE e.workspace_id = ?
                      AND e.workspace_status = 'ready'
                      AND e.session_id = ?
                      AND e.sequence_no < ?
                      AND f.text_hash = ?
                    """,
                    (workspace_id, session_id, before_sequence_no, text_hash),
                ).fetchall()
            ]
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
    ) -> None:
        if not assignments:
            return
        analysis_run_ids = {
            assignment.analysis_run_id for assignment in assignments
        }
        if len(analysis_run_ids) != 1:
            raise ValueError("lineage assignments span multiple analysis runs")
        analysis_run_id = next(iter(analysis_run_ids))
        with self._connect() as conn:
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
        fragment_ids: list[str],
    ) -> list[ArtifactContext]:
        if not fragment_ids:
            return []
        placeholders = ",".join("?" for _ in fragment_ids)
        return self._list_artifact_contexts_where(
            f"""
            WHERE e.workspace_id = ?
              AND e.workspace_status = 'ready'
              AND e.session_id = ?
              AND f.fragment_id IN ({placeholders})
            """,
            (workspace_id, session_id, *fragment_ids),
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
    if event.workspace_source == "configured_root":
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
        if event.workspace_source not in {"configured_root", "hook_cwd"}:
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
            if event.workspace_source == "configured_root"
            else None
        )
        expected_workspace = resolve_workspace(event.cwd, configured_root)
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
