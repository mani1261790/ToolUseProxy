from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import replace
from pathlib import Path

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
    SinkCandidate,
    SourceChunk,
    StoredPolicyDecision,
    ToolOperation,
)
from hook_monitor.runtime.snapshot_capture import workspace_root_from_cwd


DEFAULT_DB_PATH = Path(".tooluseproxy/events.db")


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
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
                "CREATE INDEX IF NOT EXISTS idx_artifacts_event_id ON artifacts (event_id)"
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
                ON information_flow_edges (src_node_kind, src_node_id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_information_flow_edges_dst
                ON information_flow_edges (dst_node_kind, dst_node_id)
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_resource_versions_path ON resource_versions (path)"
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
                CREATE INDEX IF NOT EXISTS idx_sink_candidates_type
                ON sink_candidates (sink_type)
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
                ON fragment_shingles (session_id, shingle, sequence_no)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_edge_scopes_session_sequence
                ON information_flow_edge_scopes (session_id, sequence_no)
                """
            )
            self._backfill_event_sequence_numbers(conn)
            self._backfill_tool_operation_outcomes(conn)

    def record(
        self,
        event: NormalizedEvent,
        artifacts: list[ArtifactRecord],
        fragments: list[ArtifactFragment] | None = None,
        operations: list[ToolOperation] | None = None,
        *,
        post_outcome: tuple[str, str] | None = None,
        resource_snapshots: list[ResourceSnapshot] | None = None,
    ) -> None:
        if resource_snapshots and any(
            snapshot.post_event_id != event.event_id
            for snapshot in resource_snapshots
        ):
            raise ValueError("resource snapshot post_event_id does not match event")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
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
                    payload_json,
                    sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            if (
                post_outcome is not None
                and event.session_id is not None
                and event.tool_use_id is not None
            ):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tool_operation_outcomes (
                        post_event_id,
                        operation_id,
                        session_id,
                        tool_use_id,
                        outcome,
                        outcome_evidence
                    )
                    SELECT ?, operation_id, session_id, tool_use_id, ?, ?
                    FROM tool_operations
                    WHERE session_id = ? AND tool_use_id = ?
                    """,
                    (
                        event.event_id,
                        post_outcome[0],
                        post_outcome[1],
                        event.session_id,
                        event.tool_use_id,
                    ),
                )
                conn.execute(
                    """
                    UPDATE tool_operations
                    SET outcome = ?, outcome_evidence = ?
                    WHERE session_id = ? AND tool_use_id = ?
                    """,
                    (
                        post_outcome[0],
                        post_outcome[1],
                        event.session_id,
                        event.tool_use_id,
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
                snapshot_operation_ids = sorted(
                    {snapshot.operation_id for snapshot in resource_snapshots}
                )
                placeholders = ",".join("?" for _ in snapshot_operation_ids)
                owner_rows = conn.execute(
                        f"""
                        SELECT
                            operation.operation_id,
                            owner.phase,
                            owner.tool_name,
                            owner.cwd
                        FROM tool_operations AS operation
                        JOIN events AS owner ON owner.event_id = operation.event_id
                        WHERE operation.operation_id IN ({placeholders})
                          AND operation.session_id = ?
                          AND operation.tool_use_id = ?
                        """,
                        (
                            *snapshot_operation_ids,
                            event.session_id,
                            event.tool_use_id,
                        ),
                    ).fetchall()
                owners = {
                    operation_id: (phase, tool_name, cwd)
                    for operation_id, phase, tool_name, cwd in owner_rows
                }
                if set(owners) != set(snapshot_operation_ids):
                    raise ValueError(
                        "resource snapshot operation does not belong to event tool use"
                    )
                event_workspace = workspace_root_from_cwd(event.cwd)
                if event.phase != "post_tool_use":
                    raise ValueError("resource snapshots require a PostToolUse event")
                for snapshot in resource_snapshots:
                    owner_phase, owner_tool_name, owner_cwd = owners[
                        snapshot.operation_id
                    ]
                    owner_workspace = workspace_root_from_cwd(owner_cwd)
                    if (
                        owner_phase != "pre_tool_use"
                        or _normalized_tool_name(owner_tool_name)
                        != _normalized_tool_name(event.tool_name)
                        or owner_workspace != event_workspace
                        or snapshot.workspace_root != owner_workspace
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
                outcome_clause = "AND event.sequence_no <= ?"
                outcome_params += (outcome_through_sequence_no,)
            outcome_rows = conn.execute(
                f"""
                SELECT
                    history.operation_id,
                    history.outcome,
                    history.outcome_evidence,
                    history.post_event_id
                FROM tool_operation_outcomes AS history
                JOIN events AS event ON event.event_id = history.post_event_id
                WHERE history.operation_id IN ({placeholders})
                  {outcome_clause}
                ORDER BY event.sequence_no DESC, history.post_event_id DESC
                """,
                outcome_params,
            ).fetchall()
        latest_outcomes: dict[str, tuple[str, str | None, str]] = {}
        for operation_id, outcome, evidence, post_event_id in outcome_rows:
            latest_outcomes.setdefault(
                operation_id,
                (outcome, evidence, post_event_id),
            )
        bounded = outcome_through_sequence_no is not None
        return [
            replace(
                operation,
                outcome=(
                    latest_outcomes[operation.operation_id][0]
                    if operation.operation_id in latest_outcomes
                    else "unknown" if bounded else operation.outcome
                ),
                outcome_evidence=(
                    latest_outcomes[operation.operation_id][1]
                    if operation.operation_id in latest_outcomes
                    else None if bounded else operation.outcome_evidence
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
        session_id: str,
        tool_use_id: str,
        *,
        outcome: str,
        evidence: str,
        post_event_id: str | None = None,
    ) -> None:
        with self._connect() as conn:
            if post_event_id is not None:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tool_operation_outcomes (
                        post_event_id,
                        operation_id,
                        session_id,
                        tool_use_id,
                        outcome,
                        outcome_evidence
                    )
                    SELECT ?, operation_id, session_id, tool_use_id, ?, ?
                    FROM tool_operations
                    WHERE session_id = ? AND tool_use_id = ?
                    """,
                    (
                        post_event_id,
                        outcome,
                        evidence,
                        session_id,
                        tool_use_id,
                    ),
                )
            conn.execute(
                """
                UPDATE tool_operations
                SET outcome = ?, outcome_evidence = ?
                WHERE session_id = ? AND tool_use_id = ?
                """,
                (outcome, evidence, session_id, tool_use_id),
            )

    def upsert_resource_snapshots(
        self,
        snapshots: list[ResourceSnapshot],
    ) -> None:
        if not snapshots:
            return
        with self._connect() as conn:
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

    def _list_resource_snapshots_where(
        self,
        where_clause: str,
        params: tuple[object, ...],
    ) -> list[ResourceSnapshot]:
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
                    s.duration_ms
                FROM resource_snapshots AS s
                JOIN events AS e ON e.event_id = s.post_event_id
                {where_clause}
                ORDER BY e.sequence_no, s.operation_id, s.path_role
                """,
                params,
            ).fetchall()
        return [ResourceSnapshot(*row) for row in rows]

    def upsert_sources(self, sources: list[ProtectedSource], chunks: list[SourceChunk]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO protected_sources (
                    source_id,
                    path,
                    source_type,
                    sensitivity,
                    policy_tags_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        source.source_id,
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
                    ordinal,
                    text,
                    normalized_text,
                    text_hash,
                    shingle_fingerprint,
                    token_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        chunk.chunk_id,
                        chunk.source_id,
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
    ) -> str:
        analysis_run_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    analysis_run_id,
                    detector_version,
                    config_json
                ) VALUES (?, ?, ?)
                """,
                (
                    analysis_run_id,
                    detector_version,
                    json.dumps(config, ensure_ascii=False, sort_keys=True),
                ),
            )
        return analysis_run_id

    def complete_analysis_run(self, analysis_run_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE analysis_runs
                SET completed_at = CURRENT_TIMESTAMP
                WHERE analysis_run_id = ?
                """,
                (analysis_run_id,),
            )

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

    def replace_information_flow_edges(self, edges: list[FlowEdge]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM information_flow_edge_scopes")
            conn.execute("DELETE FROM analysis_cursors")
            conn.execute("DELETE FROM runtime_lineage_state")
            conn.execute("DELETE FROM runtime_source_binding_edges")
            conn.execute("DELETE FROM information_flow_edges")
            conn.executemany(
                """
                INSERT OR REPLACE INTO information_flow_edges (
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
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

    def upsert_information_flow_edges_for_session(
        self,
        session_id: str,
        sequence_no: int,
        edges: list[FlowEdge],
    ) -> None:
        if not edges:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO information_flow_edges (
                    edge_id, src_node_kind, src_node_id, dst_node_kind, dst_node_id,
                    relation, evidence_level, method, score, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [_flow_edge_values(edge) for edge in edges],
            )
            conn.executemany(
                """
                INSERT INTO information_flow_edge_scopes (edge_id, session_id, sequence_no)
                VALUES (?, ?, ?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    session_id = excluded.session_id,
                    sequence_no = MIN(
                        information_flow_edge_scopes.sequence_no,
                        excluded.sequence_no
                    )
                """,
                [(edge.edge_id, session_id, sequence_no) for edge in edges],
            )

    def replace_resource_versions(self, resources: list[ResourceVersion]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM resource_versions")
            conn.executemany(
                """
                INSERT INTO resource_versions (
                    node_id,
                    path,
                    content_hash,
                    sequence_no,
                    session_id,
                    origin_tool_use_id,
                    operation_id,
                    operation_index,
                    snapshot_id,
                    resource_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        resource.node_id,
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

    def upsert_resource_versions(self, resources: list[ResourceVersion]) -> None:
        if not resources:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO resource_versions (
                    node_id, path, content_hash, sequence_no, session_id,
                    origin_tool_use_id, operation_id, operation_index,
                    snapshot_id, resource_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [_resource_values(resource) for resource in resources],
            )

    def replace_sink_candidates(self, sinks: list[SinkCandidate]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sink_candidates")
            conn.executemany(
                """
                INSERT INTO sink_candidates (
                    node_id,
                    sink_type,
                    label,
                    tool_name,
                    tool_use_id,
                    session_id,
                    sequence_no,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        sink.node_id,
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

    def upsert_sink_candidates(self, sinks: list[SinkCandidate]) -> None:
        if not sinks:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO sink_candidates (
                    node_id, sink_type, label, tool_name, tool_use_id, session_id,
                    sequence_no, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [_sink_values(sink) for sink in sinks],
            )

    def upsert_source_binding_edges(
        self,
        analysis_run_id: str,
        edges: list[FlowEdge],
    ) -> None:
        with self._connect() as conn:
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
                    (
                        analysis_run_id,
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

    def list_information_flow_edges_for_session(
        self,
        session_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    e.edge_id, e.src_node_kind, e.src_node_id, e.dst_node_kind,
                    e.dst_node_id, e.relation, e.evidence_level, e.method,
                    e.score, e.reason
                FROM information_flow_edges AS e
                JOIN information_flow_edge_scopes AS s ON s.edge_id = e.edge_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def clear_runtime_analysis_for_session(self, session_id: str) -> None:
        with self._connect() as conn:
            edge_ids = [
                row[0]
                for row in conn.execute(
                    "SELECT edge_id FROM information_flow_edge_scopes WHERE session_id = ?",
                    (session_id,),
                ).fetchall()
            ]
            conn.execute(
                "DELETE FROM information_flow_edge_scopes WHERE session_id = ?",
                (session_id,),
            )
            if edge_ids:
                placeholders = ",".join("?" for _ in edge_ids)
                conn.execute(
                    f"DELETE FROM information_flow_edges WHERE edge_id IN ({placeholders})",
                    edge_ids,
                )
            conn.execute(
                "DELETE FROM fragment_shingles WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM runtime_lineage_state WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM runtime_source_binding_edges WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM analysis_cursors WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM resource_versions WHERE session_id = ?",
                (session_id,),
            )
            conn.execute(
                "DELETE FROM sink_candidates WHERE session_id = ?",
                (session_id,),
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
                    completed_at
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
            )
            for row in rows
        ]

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
                SELECT source_id, path, source_type, sensitivity, policy_tags_json
                FROM protected_sources
                ORDER BY source_id
                """
            ).fetchall()
        return [
            ProtectedSource(
                source_id=row[0],
                path=row[1],
                source_type=row[2],
                sensitivity=row[3],
                policy_tags=tuple(json.loads(row[4])),
            )
            for row in rows
        ]

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
                    token_count
                FROM source_chunks
                ORDER BY source_id, ordinal
                """
            ).fetchall()
        return [
            SourceChunk(
                chunk_id=row[0],
                source_id=row[1],
                ordinal=row[2],
                text=row[3],
                normalized_text=row[4],
                text_hash=row[5],
                shingle_fingerprint=row[6],
                token_count=row[7],
            )
            for row in rows
        ]

    def list_resource_versions(self) -> list[ResourceVersion]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
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
                path=row[1],
                content_hash=row[2],
                sequence_no=row[3],
                session_id=row[4],
                origin_tool_use_id=row[5],
                operation_id=row[6],
                operation_index=row[7],
                snapshot_id=row[8],
                resource_state=row[9],
            )
            for row in rows
        ]

    def list_resource_versions_for_session(
        self,
        session_id: str,
    ) -> list[ResourceVersion]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT node_id, path, content_hash, sequence_no, session_id,
                       origin_tool_use_id, operation_id, operation_index,
                       snapshot_id, resource_state
                FROM resource_versions
                WHERE session_id = ?
                ORDER BY sequence_no, COALESCE(operation_index, -1), path, node_id
                """,
                (session_id,),
            ).fetchall()
        return [ResourceVersion(*row) for row in rows]

    def list_sink_candidates(self) -> list[SinkCandidate]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    node_id,
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
                sink_type=row[1],
                label=row[2],
                tool_name=row[3],
                tool_use_id=row[4],
                session_id=row[5],
                sequence_no=row[6],
                metadata=json.loads(row[7]),
            )
            for row in rows
        ]

    def list_sink_candidates_for_session(
        self,
        session_id: str,
    ) -> list[SinkCandidate]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT node_id, sink_type, label, tool_name, tool_use_id,
                       session_id, sequence_no, metadata_json
                FROM sink_candidates
                WHERE session_id = ?
                ORDER BY sequence_no, sink_type, node_id
                """,
                (session_id,),
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
            )
            for row in rows
        ]

    def replace_runtime_lineage_state(
        self,
        session_id: str,
        sequence_no: int,
        assignments: list[LineageAssignment],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM runtime_lineage_state WHERE session_id = ?",
                (session_id,),
            )
            conn.executemany(
                """
                INSERT INTO runtime_lineage_state (
                    session_id, source_node_kind, source_node_id, node_kind,
                    node_id, best_path_score, predecessor_edge_id, hop_count,
                    updated_sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
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
    ) -> None:
        if not edges:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO runtime_source_binding_edges (
                    session_id, edge_id, src_node_kind, src_node_id,
                    dst_node_kind, dst_node_id, relation, evidence_level,
                    method, score, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(session_id, *_flow_edge_values(edge)) for edge in edges],
            )

    def list_runtime_source_binding_edges(
        self,
        session_id: str,
    ) -> list[FlowEdge]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT edge_id, src_node_kind, src_node_id, dst_node_kind,
                       dst_node_id, relation, evidence_level, method, score, reason
                FROM runtime_source_binding_edges
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchall()
        return [_flow_edge_from_row(row) for row in rows]

    def upsert_runtime_lineage_state(
        self,
        session_id: str,
        sequence_no: int,
        assignments: list[LineageAssignment],
    ) -> None:
        if not assignments:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO runtime_lineage_state (
                    session_id, source_node_kind, source_node_id, node_kind,
                    node_id, best_path_score, predecessor_edge_id, hop_count,
                    updated_sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(
                    session_id, source_node_kind, source_node_id, node_kind, node_id
                ) DO UPDATE SET
                    best_path_score = excluded.best_path_score,
                    predecessor_edge_id = excluded.predecessor_edge_id,
                    hop_count = excluded.hop_count,
                    updated_sequence_no = excluded.updated_sequence_no
                WHERE excluded.best_path_score > runtime_lineage_state.best_path_score
                """,
                [
                    (
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
    ) -> list[LineageAssignment]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_node_kind, source_node_id, node_kind, node_id,
                       best_path_score, predecessor_edge_id, hop_count
                FROM runtime_lineage_state
                WHERE session_id = ?
                """,
                (session_id,),
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

    def get_analysis_cursor(self, session_id: str) -> AnalysisCursor | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT session_id, detector_version, source_digest,
                       last_sequence_no, status
                FROM analysis_cursors
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return AnalysisCursor(
            session_id=row[0],
            detector_version=row[1],
            source_digest=row[2],
            last_sequence_no=row[3],
            status=row[4],
        )

    def upsert_analysis_cursor(self, cursor: AnalysisCursor) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO analysis_cursors (
                    session_id, detector_version, source_digest,
                    last_sequence_no, status
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    detector_version = excluded.detector_version,
                    source_digest = excluded.source_digest,
                    last_sequence_no = excluded.last_sequence_no,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
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
    ) -> None:
        rows = [
            (
                context.fragment.fragment_id,
                session_id,
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
            conn.executemany(
                """
                INSERT OR IGNORE INTO fragment_shingles (
                    fragment_id, session_id, sequence_no, shingle
                ) VALUES (?, ?, ?, ?)
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
                    JOIN fragment_shingles AS i ON i.fragment_id = f.fragment_id
                    WHERE e.session_id = ? AND e.sequence_no < ? AND f.text_hash = ?
                    """,
                    (session_id, before_sequence_no, text_hash),
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
                        WHERE session_id = ? AND sequence_no < ?
                          AND shingle IN ({placeholders})
                        GROUP BY fragment_id
                        ORDER BY overlap_count DESC, fragment_id
                        LIMIT ?
                        """,
                        (session_id, before_sequence_no, *values, limit),
                    ).fetchall()
                ]
        return list(dict.fromkeys(exact + overlap))

    def upsert_lineage_assignments(
        self,
        assignments: list[LineageAssignment],
    ) -> None:
        with self._connect() as conn:
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

    def list_artifact_contexts(self) -> list[ArtifactContext]:
        return self._list_artifact_contexts_where("", ())

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
                    e.sequence_no
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
