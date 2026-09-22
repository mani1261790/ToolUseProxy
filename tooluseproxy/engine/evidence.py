"""Versioned evidence ledger. Facts, inferred claims and coverage are distinct."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from tooluseproxy.engine.graph import digest

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Resource:
    scope: str
    kind: str
    locator: str

    @property
    def identity(self):
        return digest(asdict(self))


@dataclass(frozen=True)
class ContentVersion:
    resource: Resource
    token: str
    evidence_event: str
    byte_length: int | None = None

    @property
    def identity(self):
        return digest([self.resource.identity, self.token])


@dataclass(frozen=True)
class EvidenceNeed:
    kind: Literal["resource_version", "target_extent", "execution_definition", "location", "origin"]
    target: str
    reason: str


DDL = (
    "CREATE TABLE IF NOT EXISTS flow_schema (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)",
    """CREATE TABLE IF NOT EXISTS flow_observations (
        scope TEXT NOT NULL, event TEXT NOT NULL, session TEXT, call_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK(phase IN ('pre_tool_use','post_tool_use')), sequence INTEGER NOT NULL,
        PRIMARY KEY(scope,event), UNIQUE(scope,sequence))""",
    """CREATE TABLE IF NOT EXISTS flow_resources (
        scope TEXT NOT NULL, resource TEXT NOT NULL, kind TEXT NOT NULL, locator TEXT NOT NULL,
        PRIMARY KEY(scope,resource), UNIQUE(scope,kind,locator))""",
    """CREATE TABLE IF NOT EXISTS flow_versions (
        scope TEXT NOT NULL, version TEXT NOT NULL, resource TEXT NOT NULL, token TEXT NOT NULL,
        byte_length INTEGER CHECK(byte_length IS NULL OR byte_length>=0),
        PRIMARY KEY(scope,version), UNIQUE(scope,resource,token),
        FOREIGN KEY(scope,resource) REFERENCES flow_resources(scope,resource))""",
    """CREATE TABLE IF NOT EXISTS flow_version_evidence (
        scope TEXT NOT NULL, version TEXT NOT NULL, event TEXT NOT NULL,
        PRIMARY KEY(scope,version,event),
        FOREIGN KEY(scope,version) REFERENCES flow_versions(scope,version),
        FOREIGN KEY(scope,event) REFERENCES flow_observations(scope,event))""",
    """CREATE TABLE IF NOT EXISTS flow_accesses (
        scope TEXT NOT NULL, access TEXT NOT NULL, event TEXT NOT NULL, version TEXT NOT NULL,
        mode TEXT NOT NULL CHECK(mode IN ('read','write')),
        status TEXT NOT NULL CHECK(status IN ('planned','observed')),
        basis TEXT NOT NULL CHECK(basis IN ('observation','inference')),
        extent_json TEXT NOT NULL, reason TEXT NOT NULL,
        PRIMARY KEY(scope,access),
        FOREIGN KEY(scope,event) REFERENCES flow_observations(scope,event),
        FOREIGN KEY(scope,version) REFERENCES flow_versions(scope,version))""",
    "CREATE INDEX IF NOT EXISTS flow_version_accesses ON flow_accesses(scope,version,status,mode)",
    """CREATE TABLE IF NOT EXISTS flow_transmissions (
        scope TEXT NOT NULL, unit TEXT NOT NULL, event TEXT NOT NULL,
        description_json TEXT NOT NULL, destination_json TEXT NOT NULL,
        PRIMARY KEY(scope,unit), FOREIGN KEY(scope,event) REFERENCES flow_observations(scope,event))""",
    """CREATE TABLE IF NOT EXISTS flow_resolutions (
        scope TEXT NOT NULL, resolution TEXT NOT NULL, unit TEXT NOT NULL,
        resolver_version TEXT NOT NULL, evidence_json TEXT NOT NULL,
        coverage TEXT NOT NULL CHECK(coverage IN ('complete','partial','unsupported','failed')),
        reason TEXT NOT NULL, PRIMARY KEY(scope,resolution),
        FOREIGN KEY(scope,unit) REFERENCES flow_transmissions(scope,unit))""",
    """CREATE TABLE IF NOT EXISTS flow_resolution_members (
        scope TEXT NOT NULL, resolution TEXT NOT NULL, version TEXT NOT NULL, extent_json TEXT NOT NULL,
        PRIMARY KEY(scope,resolution,version,extent_json),
        FOREIGN KEY(scope,resolution) REFERENCES flow_resolutions(scope,resolution),
        FOREIGN KEY(scope,version) REFERENCES flow_versions(scope,version))""",
    """CREATE TABLE IF NOT EXISTS flow_needs (
        scope TEXT NOT NULL, need TEXT NOT NULL, event TEXT NOT NULL, kind TEXT NOT NULL,
        target TEXT NOT NULL, reason TEXT NOT NULL,
        PRIMARY KEY(scope,need), FOREIGN KEY(scope,event) REFERENCES flow_observations(scope,event))""",
    """CREATE TABLE IF NOT EXISTS flow_need_attempts (
        scope TEXT NOT NULL, need TEXT NOT NULL, attempt INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('resolved','unsupported','failed','exhausted')),
        evidence_json TEXT NOT NULL, reason TEXT NOT NULL,
        PRIMARY KEY(scope,need,attempt), FOREIGN KEY(scope,need) REFERENCES flow_needs(scope,need))""",
)


def migrate(conn):
    # Caller owns the transaction; no executescript (which would commit it).
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name='flow_schema'").fetchone()
    if exists:
        row = conn.execute("SELECT version FROM flow_schema WHERE id=1").fetchone()
        if row and row[0] != SCHEMA_VERSION:
            raise ValueError("unsupported_flow_schema")
    for statement in DDL:
        conn.execute(statement)
    if not exists and conn.execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone():
        conn.execute("""INSERT OR IGNORE INTO flow_observations
            SELECT workspace_id,event_id,session_id,tool_use_id,phase,sequence_no FROM events
            WHERE workspace_id IS NOT NULL AND tool_use_id IS NOT NULL AND sequence_no IS NOT NULL
            AND phase IN ('pre_tool_use','post_tool_use')""")
    conn.execute("INSERT INTO flow_schema VALUES (1,?) ON CONFLICT DO NOTHING", (SCHEMA_VERSION,))


def observe(conn, event, sequence):
    if event.tool_use_id and event.phase in ("pre_tool_use", "post_tool_use"):
        conn.execute(
            "INSERT INTO flow_observations VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            (
                event.workspace_id,
                event.event_id,
                event.session_id,
                event.tool_use_id,
                event.phase,
                sequence,
            ),
        )


class EvidenceStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def transaction(self):
        conn = sqlite3.connect(self.path, timeout=5)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("BEGIN IMMEDIATE")
            migrate(conn)
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        with self.transaction():
            pass

    def add_version(self, value: ContentVersion):
        if not value.token or not value.resource.scope or not value.resource.locator:
            raise ValueError("invalid_resource_version")
        with self.transaction() as conn:
            r = value.resource
            conn.execute(
                "INSERT INTO flow_resources VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
                (r.scope, r.identity, r.kind, r.locator),
            )
            old = conn.execute(
                "SELECT byte_length FROM flow_versions WHERE scope=? AND version=?",
                (r.scope, value.identity),
            ).fetchone()
            if old and old[0] != value.byte_length:
                raise ValueError("conflicting_version_evidence")
            conn.execute(
                "INSERT INTO flow_versions VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
                (r.scope, value.identity, r.identity, value.token, value.byte_length),
            )
            conn.execute(
                "INSERT INTO flow_version_evidence VALUES (?,?,?) ON CONFLICT DO NOTHING",
                (r.scope, value.identity, value.evidence_event),
            )
        return value.identity

    def add_access(self, value: ContentVersion, mode, status, basis, extent, reason):
        scope = value.resource.scope
        data = [value.evidence_event, value.identity, mode, status, basis, extent, reason]
        identity = digest(data)
        with self.transaction() as conn:
            phase = conn.execute(
                "SELECT phase FROM flow_observations WHERE scope=? AND event=?",
                (scope, value.evidence_event),
            ).fetchone()
            if status == "observed" and (not phase or phase[0] != "post_tool_use"):
                raise ValueError("unexecuted_access_cannot_be_observed")
            conn.execute(
                "INSERT INTO flow_accesses VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (
                    scope,
                    identity,
                    value.evidence_event,
                    value.identity,
                    mode,
                    status,
                    basis,
                    json.dumps(extent, sort_keys=True),
                    reason,
                ),
            )
        return identity

    def add_transmission(self, scope, event, description, destination):
        identity = digest([scope, event, description, destination])
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO flow_transmissions VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
                (
                    scope,
                    identity,
                    event,
                    json.dumps(description, sort_keys=True),
                    json.dumps(destination, sort_keys=True),
                ),
            )
        return identity

    def add_resolution(self, scope, unit, resolver_version, coverage, reason, evidence, members):
        members = sorted(members, key=lambda item: (item[0], json.dumps(item[1], sort_keys=True)))
        identity = digest([scope, unit, resolver_version, coverage, reason, evidence, members])
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO flow_resolutions VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (
                    scope,
                    identity,
                    unit,
                    resolver_version,
                    json.dumps(evidence, sort_keys=True),
                    coverage,
                    reason,
                ),
            )
            conn.executemany(
                "INSERT INTO flow_resolution_members VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
                [
                    (scope, identity, version, json.dumps(extent, sort_keys=True))
                    for version, extent in members
                ],
            )
        return identity

    def add_need(self, scope, event, need: EvidenceNeed):
        if need.kind not in (
            "resource_version",
            "target_extent",
            "execution_definition",
            "location",
            "origin",
        ):
            raise ValueError("invalid_evidence_need")
        identity = digest([scope, event, asdict(need)])
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO flow_needs VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (scope, identity, event, need.kind, need.target, need.reason),
            )
        return identity

    def record_attempt(self, scope, need, status, evidence, reason, max_attempts=3):
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT status,evidence_json FROM flow_need_attempts WHERE scope=? AND need=? ORDER BY attempt",
                (scope, need),
            ).fetchall()
            encoded = json.dumps(evidence, sort_keys=True)
            if len(rows) >= max_attempts or any(
                row[0] == "resolved" or row[1] == encoded for row in rows
            ):
                raise ValueError("evidence_attempt_not_progressing")
            conn.execute(
                "INSERT INTO flow_need_attempts VALUES (?,?,?,?,?,?)",
                (scope, need, len(rows) + 1, status, encoded, reason),
            )
