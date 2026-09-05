"""Optional evaluation storage; failures must not change protection decisions."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, fields
from pathlib import Path

from hook_monitor.runtime.pilot_models import (
    CauseCategory, EvidenceSource, Externality, PayloadResolution, PilotObservation,
    PolicyAction, ReasonCode, RecordState, ReviewState, StudyCohort, ToolFamily,
)

ENUM_FIELDS = {
    "tool_family": ToolFamily,
    "externality": Externality,
    "payload_resolution": PayloadResolution,
    "evidence_source": EvidenceSource,
    "policy_action": PolicyAction,
    "reason_code": ReasonCode,
    "review_state": ReviewState,
    "cause_candidate": CauseCategory,
    "record_state": RecordState,
    "study_cohort": StudyCohort,
}
COLUMNS = tuple(field.name for field in fields(PilotObservation))


def initialize_pilot_schema(conn: sqlite3.Connection) -> None:
    columns = []
    for name in COLUMNS:
        if name in ENUM_FIELDS:
            options = ", ".join("'" + value.value + "'" for value in ENUM_FIELDS[name])
            nullable = "" if name == "cause_candidate" else "NOT NULL"
            columns.append(f"{name} TEXT {nullable} CHECK ({name} IN ({options}))")
        elif name == "decision_ms":
            columns.append("decision_ms REAL NOT NULL CHECK (decision_ms BETWEEN 0 AND 60000)")
        elif name in {"event_ref_sha256", "settings_revision"}:
            columns.append(
                f"{name} TEXT NOT NULL CHECK (length({name}) = 64 "
                f"AND {name} NOT GLOB '*[^0-9a-f]*')"
            )
        elif name == "workspace_id":
            columns.append(
                "workspace_id TEXT NOT NULL CHECK (length(workspace_id) = 70 "
                "AND substr(workspace_id, 1, 6) = 'ws_v1_' "
                "AND substr(workspace_id, 7) NOT GLOB '*[^0-9a-f]*')"
            )
        else:
            columns.append(f"{name} TEXT NOT NULL CHECK (length({name}) BETWEEN 1 AND 128)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pilot_observations ("
        + ", ".join(columns)
        + ", PRIMARY KEY (observation_id), UNIQUE (workspace_id, event_ref_sha256), "
        "CHECK ((policy_action = 'allow' AND review_state = 'not_needed') OR "
        "(policy_action = 'block' AND review_state != 'not_needed')))"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pilot_workspace_version "
        "ON pilot_observations (workspace_id, detector_version, observed_at)"
    )
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS pilot_observations_no_update "
        "BEFORE UPDATE ON pilot_observations BEGIN "
        "SELECT RAISE(ABORT, 'pilot observation is immutable'); END"
    )


def store_pilot_observation(db_path: Path, item: PilotObservation) -> None:
    # Revalidate even if a caller bypassed frozen dataclass construction.
    item = PilotObservation(**asdict(item))
    values = tuple(getattr(item, name) for name in COLUMNS)
    with sqlite3.connect(db_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=0.01) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            f"SELECT {', '.join(COLUMNS)} FROM pilot_observations "
            "WHERE workspace_id = ? AND event_ref_sha256 = ?",
            (item.workspace_id, item.event_ref_sha256),
        ).fetchone()
        if existing is not None:
            # Replay keeps the original timestamp, duration, and generated ID.
            stable = set(COLUMNS) - {"observation_id", "observed_at", "decision_ms", "record_state"}
            if any(existing[COLUMNS.index(name)] != getattr(item, name) for name in stable):
                raise ValueError("pilot replay mismatch")
            return
        conn.execute(
            f"INSERT INTO pilot_observations ({', '.join(COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in COLUMNS)})",
            values,
        )


def list_pilot_observations(db_path: Path, *, workspace_id: str) -> tuple[PilotObservation, ...]:
    with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.01) as conn:
        rows = conn.execute(
            f"SELECT {', '.join(COLUMNS)} FROM pilot_observations "
            "WHERE workspace_id = ? ORDER BY observed_at, observation_id",
            (workspace_id,),
        ).fetchall()
    result = []
    for row in rows:
        values = dict(zip(COLUMNS, row, strict=True))
        for name, enum in ENUM_FIELDS.items():
            if values[name] is not None:
                values[name] = enum(values[name])
        result.append(PilotObservation(**values))
    return tuple(result)
