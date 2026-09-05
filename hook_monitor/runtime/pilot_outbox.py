"""Durable, content-free proposals. Enqueuing does not contact GitHub."""

from __future__ import annotations

import json
import sqlite3
import os
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from hook_monitor.runtime.pilot_issue import proposals_for_comparison, proposal_document, validate_document


def initialize_pilot_outbox_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_issue_outbox (
        delivery_key TEXT PRIMARY KEY NOT NULL,
        problem_key TEXT NOT NULL,
        comparison_id TEXT NOT NULL,
        proposal_json TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sent')),
        issue_number INTEGER CHECK(issue_number > 0),
        last_error TEXT CHECK(last_error IN
            ('missing_cli','unauthenticated','network','invalid','ambiguous','unconfigured'))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_issue_bindings (
        problem_key TEXT PRIMARY KEY NOT NULL,
        repository TEXT NOT NULL,
        issue_number INTEGER NOT NULL CHECK(issue_number > 0)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_issue_preparations (
        comparison_id TEXT PRIMARY KEY NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('prepared','rejected'))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_issue_config (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        repository TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
    )""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS pilot_issue_outbox_fixed_proposal
        BEFORE UPDATE ON pilot_issue_outbox WHEN
        NEW.delivery_key != OLD.delivery_key OR NEW.problem_key != OLD.problem_key OR
        NEW.comparison_id != OLD.comparison_id OR NEW.proposal_json != OLD.proposal_json
        BEGIN SELECT RAISE(ABORT, 'proposal is immutable'); END""")


def enqueue_comparisons(path: Path) -> int:
    inserted = 0
    with sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=0.01) as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("SELECT comparison_id, report_json FROM pilot_comparisons c "
                            "WHERE NOT EXISTS (SELECT 1 FROM pilot_issue_preparations p "
                            "WHERE p.comparison_id = c.comparison_id) ORDER BY c.rowid LIMIT 100").fetchall()
        for identifier, report_json in rows:
            try:
                items = proposals_for_comparison(identifier, json.loads(report_json))
                for item in items:
                    title, body = proposal_document(item)
                    validate_document(item, title=title, body=body)
            except (ValueError, TypeError, KeyError, RecursionError):
                conn.execute("INSERT INTO pilot_issue_preparations VALUES (?, 'rejected')", (identifier,))
                continue
            for item in items:
                cursor = conn.execute("INSERT OR IGNORE INTO pilot_issue_outbox "
                                      "(delivery_key, problem_key, comparison_id, proposal_json) VALUES (?,?,?,?)",
                                      (item.delivery_key, item.problem_key, item.comparison_id,
                                       json.dumps(asdict(item), sort_keys=True, allow_nan=False)))
                inserted += cursor.rowcount
            conn.execute("INSERT INTO pilot_issue_preparations VALUES (?, 'prepared')", (identifier,))
    return inserted


def configure_sync(path: Path, *, repository: str, enabled: bool) -> None:
    if not isinstance(enabled, bool) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository
    ):
        raise ValueError("invalid synchronization configuration")
    with sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=1) as conn:
        # A destination with existing bindings cannot silently redirect them.
        if conn.execute("SELECT 1 FROM pilot_issue_bindings WHERE repository != ? LIMIT 1",
                        (repository,)).fetchone():
            raise ValueError("existing issue bindings use a different repository")
        conn.execute("INSERT INTO pilot_issue_config VALUES (1,?,?) ON CONFLICT(singleton) "
                     "DO UPDATE SET repository=excluded.repository, enabled=excluded.enabled",
                     (repository, int(enabled)))


def sync_configuration(path: Path) -> tuple[str, bool]:
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.01) as conn:
        row = conn.execute("SELECT repository, enabled FROM pilot_issue_config WHERE singleton=1").fetchone()
    repository = os.environ.get("TOOLUSEPROXY_PILOT_ISSUE_REPOSITORY", row[0] if row else "")
    configured = os.environ.get("TOOLUSEPROXY_PILOT_ISSUE_SYNC")
    enabled = configured == "1" if configured is not None else bool(row and row[1])
    return repository, enabled


def start_pending_worker(path: Path, *, workspace_root: Path) -> bool:
    """Opt-in launch only. This process does not wait for or contact GitHub."""
    repository, enabled = sync_configuration(path)
    if not enabled or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository
    ):
        return False
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.01) as conn:
        if conn.execute("SELECT 1 FROM pilot_issue_outbox WHERE state='pending' LIMIT 1").fetchone() is None:
            return False
    entrypoint = Path(__file__).resolve().parents[2] / "tooluseproxy_plugin.py"
    command = ([sys.executable, str(entrypoint)] if entrypoint.is_file()
               else [sys.executable, "-m", "tooluseproxy"])
    subprocess.Popen(
        [*command, "pilot", "sync", "--db", str(path),
         "--workspace", str(workspace_root), "--repository", repository],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )
    return True
