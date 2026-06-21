from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from hook_monitor.runtime.models import (
    ArtifactRecord,
    FlowEdge,
    NormalizedEvent,
    ProtectedSource,
    SourceChunk,
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
                "CREATE INDEX IF NOT EXISTS idx_events_tool_use_id ON events (tool_use_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_session_turn ON events (session_id, turn_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_event_id ON artifacts (event_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_chunks_source_id ON source_chunks (source_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flow_edges_dst_artifact_id ON flow_edges (dst_artifact_id)"
            )

    def record(self, event: NormalizedEvent, artifacts: list[ArtifactRecord]) -> None:
        with self._connect() as conn:
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
                    payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def upsert_flow_edges(self, edges: list[FlowEdge]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO flow_edges (
                    edge_id,
                    src_node_kind,
                    src_node_id,
                    dst_artifact_id,
                    method,
                    score,
                    reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        edge.edge_id,
                        edge.src_node_kind,
                        edge.src_node_id,
                        edge.dst_artifact_id,
                        edge.method,
                        edge.score,
                        edge.reason,
                    )
                    for edge in edges
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

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)
