"""Atomic local comparisons; deliberately contains no network operations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from hook_monitor.runtime.models import NormalizedEvent
from hook_monitor.runtime.pilot_aggregate import build_pilot_comparisons
from hook_monitor.runtime.pilot_coverage import read_task_coverage
from hook_monitor.runtime.pilot_review import comparison_inputs
from hook_monitor.runtime.pilot_models import PILOT_COMPARISON_THRESHOLD, ToolFamily


def initialize_pilot_stop_schema(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS pilot_project_aliases "
                 "(alias_number INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT UNIQUE NOT NULL)")
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_comparisons (
        comparison_id TEXT PRIMARY KEY NOT NULL,
        detector_version TEXT NOT NULL,
        round_number INTEGER NOT NULL CHECK(round_number > 0),
        report_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        UNIQUE(detector_version, round_number)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_coverage_snapshots (
        stop_ref_sha256 TEXT PRIMARY KEY NOT NULL,
        workspace_id TEXT NOT NULL,
        session_ref_sha256 TEXT NOT NULL,
        counts_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )""")
    for table in ("pilot_comparisons", "pilot_coverage_snapshots"):
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} "
                     "BEGIN SELECT RAISE(ABORT, 'pilot result is immutable'); END")


def _connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                           uri=True, timeout=0.01)


def compare_on_stop(path: Path, *, event: NormalizedEvent, codex_home: Path) -> tuple[str, ...]:
    if not event.workspace_id or not event.workspace_root or not event.session_id:
        return ()
    with closing(_connect(path, readonly=True)) as conn:
        hook_ids = {hashlib.sha256(row[0].encode()).hexdigest() for row in conn.execute(
            "SELECT tool_use_id FROM events WHERE workspace_id = ? AND session_id = ? "
            "AND phase = 'pre_tool_use' AND tool_use_id IS NOT NULL",
            (event.workspace_id, event.session_id),
        )}
    coverage = read_task_coverage(
        Path(event.transcript_path) if event.transcript_path else None,
        session_id=event.session_id, workspace_root=Path(event.workspace_root),
        codex_home=codex_home, hook_call_hashes=hook_ids,
    )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    created = []
    with closing(_connect(path)) as connection, connection as conn:
        # Every evaluator/reviewer uses SQLite writes. Holding this reservation
        # makes the following multi-project reads a stable snapshot and avoids
        # duplicate rounds even if two Stop hooks arrive together.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO pilot_coverage_snapshots VALUES (?,?,?,?,?)", (
            hashlib.sha256(event.event_id.encode()).hexdigest(), event.workspace_id,
            hashlib.sha256(event.session_id.encode()).hexdigest(), json.dumps(coverage, sort_keys=True), now,
        ))
        ready = conn.execute("""SELECT detector_version FROM (
            SELECT o.detector_version, o.workspace_id, COUNT(*) AS available,
                ? * (1 + COALESCE((SELECT MAX(round_number) FROM pilot_comparisons c
                                   WHERE c.detector_version = o.detector_version), 0)) AS required
            FROM pilot_observations o WHERE study_cohort = 'pilot' AND record_state != 'incomplete'
                AND (review_state != 'pending' OR EXISTS
                     (SELECT 1 FROM pilot_reviews r WHERE r.observation_id = o.observation_id))
            GROUP BY o.detector_version, o.workspace_id
        ) WHERE available >= required GROUP BY detector_version HAVING COUNT(*) >= 2""",
            (PILOT_COMPARISON_THRESHOLD,),
        ).fetchall()
        if not ready:
            return ()
        workspaces = [row[0] for row in conn.execute(
            "SELECT DISTINCT workspace_id FROM pilot_observations ORDER BY workspace_id")]
        observations, problems = [], []
        for workspace_id in workspaces:
            conn.execute("INSERT INTO pilot_project_aliases(workspace_id) "
                         "SELECT ? WHERE NOT EXISTS (SELECT 1 FROM pilot_project_aliases WHERE workspace_id = ?)",
                         (workspace_id, workspace_id))
            items, issues = comparison_inputs(path, workspace_id=workspace_id)
            observations.extend(items)
            problems.extend(issues)
        aliases = {row[1]: f"project_{row[0]}" for row in conn.execute(
            "SELECT alias_number, workspace_id FROM pilot_project_aliases")}
        for report in build_pilot_comparisons(observations, problems, project_aliases=aliases):
            version = report["comparison"]["detector_version"]
            round_number = report["comparison"]["round"]
            identifier = hashlib.sha256(f"pilot-comparison-v1:{version}:{round_number}".encode()).hexdigest()
            exists = conn.execute("SELECT 1 FROM pilot_comparisons WHERE comparison_id = ?",
                                  (identifier,)).fetchone()
            if exists:
                continue
            participant_aliases = {item["project"] for item in report["projects"]}
            participants = {key for key, alias in aliases.items() if alias in participant_aliases}
            report["coverage"] = _coverage_summary(conn, participants)
            report["limitations"]["recording_gap_count_unknown"] = True
            conn.execute("INSERT INTO pilot_comparisons VALUES (?,?,?,?,?)", (
                identifier, version, round_number, json.dumps(report, sort_keys=True, allow_nan=False), now,
            ))
            created.append(identifier)
    return tuple(created)


def _coverage_summary(conn: sqlite3.Connection, participants: set[str]) -> dict:
    known, unknown, missing_projects = [], 0, 0
    for workspace_id in participants:
        rows = conn.execute("SELECT c.counts_json FROM pilot_coverage_snapshots c "
                            "WHERE c.workspace_id = ? AND c.rowid IN "
                            "(SELECT MAX(rowid) FROM pilot_coverage_snapshots WHERE workspace_id = ? "
                            "GROUP BY session_ref_sha256)", (workspace_id, workspace_id)).fetchall()
        if not rows:
            missing_projects += 1
        for row in rows:
            counts = json.loads(row[0])
            if counts["status"] == "known":
                known.append(counts)
            else:
                unknown += 1
    return {
        "scope": "latest_local_task_snapshots",
        "same_detector_version_guaranteed": False,
        "known_task_count": len(known), "unknown_task_count": unknown,
        "projects_without_task_records": missing_projects,
        "observed_calls": sum(item["observed_calls"] for item in known) if known else None,
        "hook_matched": sum(item["hook_matched"] for item in known) if known else None,
        "hook_unmatched": sum(item["hook_unmatched"] for item in known) if known else None,
        "unmatched_by_family": {
            str(family): sum(item["unmatched_by_family"][str(family)] for item in known) if known else None
            for family in ToolFamily
        },
    }


def list_comparisons(path: Path) -> tuple[dict, ...]:
    with closing(_connect(path, readonly=True)) as conn:
        return tuple({"comparison_id": row[0], "report": json.loads(row[1])}
                     for row in conn.execute("SELECT comparison_id, report_json FROM pilot_comparisons "
                                             "ORDER BY recorded_at, comparison_id"))
