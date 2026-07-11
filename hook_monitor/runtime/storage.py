from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

from hook_monitor.runtime.models import (
    AnalysisRun,
    ArtifactContext,
    ArtifactFragment,
    ArtifactRecord,
    FlowEdge,
    LineageAssignment,
    NormalizedEvent,
    ProtectedSource,
    ResourceVersion,
    SinkCandidate,
    SourceChunk,
    StoredPolicyDecision,
)


DEFAULT_DB_PATH = Path(".tooluseproxy/events.db")


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
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
                "CREATE INDEX IF NOT EXISTS idx_artifacts_event_id ON artifacts (event_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fragments_artifact_id ON artifact_fragments (artifact_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fragments_text_hash ON artifact_fragments (text_hash)"
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
            self._backfill_event_sequence_numbers(conn)

    def record(
        self,
        event: NormalizedEvent,
        artifacts: list[ArtifactRecord],
        fragments: list[ArtifactFragment] | None = None,
    ) -> None:
        with self._connect() as conn:
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
                    payload_json,
                    sequence_no
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        token_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                        )
                        for fragment in fragments
                    ],
                )

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
                    token_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                    origin_tool_use_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        resource.node_id,
                        resource.path,
                        resource.content_hash,
                        resource.sequence_no,
                        resource.session_id,
                        resource.origin_tool_use_id,
                    )
                    for resource in resources
                ],
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
                    origin_tool_use_id
                FROM resource_versions
                ORDER BY sequence_no, path, node_id
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
            )
            for row in rows
        ]

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
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    f.fragment_id,
                    f.artifact_id,
                    f.json_pointer,
                    f.semantic_role,
                    f.text,
                    f.text_hash,
                    f.normalized_text,
                    f.token_count,
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
                ORDER BY e.sequence_no, f.fragment_id
                """
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
                ),
                artifact_role=row[8],
                event_id=row[9],
                phase=row[10],
                session_id=row[11],
                turn_id=row[12],
                tool_use_id=row[13],
                tool_name=row[14],
                cwd=row[15],
                sequence_no=row[16],
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

    def _next_sequence_no(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM events"
        ).fetchone()
        return int(row[0])

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)


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
