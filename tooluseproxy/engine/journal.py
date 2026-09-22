"""Append ToolCall observations without invoking an analysis or migration pipeline."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tooluseproxy.engine.identity import make_event_id
from tooluseproxy.engine.evidence import migrate, observe
from tooluseproxy.engine.workspace import resolve_workspace


@dataclass(frozen=True)
class Event:
    event_id: str
    phase: str
    workspace_id: str
    workspace_root: str
    session_id: str | None
    tool_use_id: str | None
    raw_payload: dict


def event_from(phase: str, payload: dict, root: str) -> Event:
    workspace = resolve_workspace(payload.get("cwd"), root)
    if not workspace.ready:
        raise ValueError("workspace_unavailable")
    return Event(
        make_event_id(phase, payload, workspace_namespace_id=workspace.workspace_id),
        phase,
        workspace.workspace_id,
        workspace.canonical_root,
        payload.get("session_id"),
        payload.get("tool_use_id"),
        payload,
    )


@dataclass(frozen=True)
class Source:
    source_id: str
    path: str
    source_type: str
    sensitivity: str
    policy_tags: tuple
    workspace_id: str
    source_key: str
    selector: object


class Journal:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def initialize(self):
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            if (
                columns
                and not {"event_id", "workspace_id", "session_id", "sequence_no", "payload_json"}
                <= columns
            ):
                raise ValueError("legacy_database_migration_required")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS engine_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT OR IGNORE INTO engine_metadata VALUES ('engine','semantic-flow-v2');
                CREATE TABLE IF NOT EXISTS workspaces (
                    workspace_id TEXT PRIMARY KEY, canonical_root TEXT NOT NULL UNIQUE,
                    lexical_root TEXT NOT NULL, discovered_by TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY, phase TEXT NOT NULL, session_id TEXT,
                    turn_id TEXT, tool_use_id TEXT, tool_name TEXT, cwd TEXT, model TEXT,
                    permission_mode TEXT, transcript_path TEXT, stop_hook_active INTEGER,
                    workspace_id TEXT, workspace_root TEXT, workspace_lexical_root TEXT,
                    workspace_execution_cwd TEXT, workspace_status TEXT NOT NULL DEFAULT 'ready',
                    workspace_source TEXT, workspace_namespace_id TEXT, payload_json TEXT NOT NULL,
                    sequence_no INTEGER, recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE INDEX IF NOT EXISTS semantic_events_scope
                    ON events(workspace_id,session_id,sequence_no);
                CREATE TABLE IF NOT EXISTS protected_sources (
                    source_id TEXT PRIMARY KEY, path TEXT NOT NULL, source_type TEXT NOT NULL,
                    sensitivity TEXT NOT NULL, policy_tags_json TEXT NOT NULL,
                    selector_json TEXT NOT NULL DEFAULT 'null', workspace_id TEXT, source_key TEXT,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            """)

            migrate(conn)

    def register_workspace(self, root: str):
        workspace = resolve_workspace(root, root)
        if not workspace.ready:
            raise ValueError("workspace_unavailable")
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            conn.execute(
                "INSERT INTO workspaces(workspace_id,canonical_root,lexical_root,discovered_by) "
                "VALUES (?,?,?,?) ON CONFLICT(workspace_id) DO NOTHING",
                (workspace.workspace_id, workspace.canonical_root, root, "init"),
            )
        return workspace

    def record(self, event, artifacts=None):
        if not self.db_path.is_file():
            raise ValueError("database_missing")
        del artifacts
        payload = event.raw_payload
        scope = resolve_workspace(payload.get("cwd"), event.workspace_root)
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT sequence_no FROM events WHERE event_id=?", (event.event_id,)
            ).fetchone()
            if existing:
                migrate(conn)
                observe(conn, event, existing[0])
                return
            sequence = conn.execute("SELECT COALESCE(MAX(sequence_no),0)+1 FROM events").fetchone()[
                0
            ]
            conn.execute(
                """INSERT INTO events (
                event_id,phase,session_id,turn_id,tool_use_id,tool_name,cwd,model,permission_mode,
                transcript_path,stop_hook_active,workspace_id,workspace_root,workspace_lexical_root,
                workspace_execution_cwd,workspace_status,workspace_source,workspace_namespace_id,
                payload_json,sequence_no) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id,
                    event.phase,
                    event.session_id,
                    payload.get("turn_id"),
                    event.tool_use_id,
                    payload.get("tool_name"),
                    payload.get("cwd"),
                    payload.get("model"),
                    payload.get("permission_mode"),
                    payload.get("transcript_path"),
                    payload.get("stop_hook_active"),
                    event.workspace_id,
                    event.workspace_root,
                    scope.lexical_root,
                    scope.execution_cwd,
                    scope.status,
                    "registered_root",
                    event.workspace_id,
                    json.dumps(payload, ensure_ascii=False),
                    sequence,
                ),
            )
            migrate(conn)
            observe(conn, event, sequence)

    def list_protected_sources_for_workspace(self, workspace: str):
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            rows = conn.execute(
                "SELECT source_id,path,source_type,sensitivity,policy_tags_json,"
                "workspace_id,source_key,selector_json FROM protected_sources "
                "WHERE workspace_id=? ORDER BY source_id",
                (workspace,),
            ).fetchall()
        return [
            Source(*row[:4], tuple(json.loads(row[4])), row[5], row[6], json.loads(row[7]))
            for row in rows
        ]
