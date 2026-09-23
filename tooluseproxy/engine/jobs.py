"""Durable, leased provenance jobs. Never keep a DB write lock while judging."""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_jobs (
        scope TEXT NOT NULL,event TEXT NOT NULL,session TEXT NOT NULL,model TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','running','done','failed','paused')),
        owner TEXT,lease_until REAL NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL DEFAULT '',PRIMARY KEY(scope,event,model))""")
    conn.execute("CREATE INDEX IF NOT EXISTS flow_job_queue ON flow_jobs(scope,status,lease_until)")


@contextmanager
def transaction(db):
    conn = sqlite3.connect(db, timeout=5)
    try:
        conn.execute("BEGIN IMMEDIATE")
        schema(conn)
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def enqueue(db, event, model):
    if event.phase != "post_tool_use":
        return
    with transaction(db) as conn:
        conn.execute(
            "INSERT INTO flow_jobs(scope,event,session,model,status) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
            (event.workspace_id, event.event_id, event.session_id, model, "pending"),
        )


def claim(db, scope, now=None):
    now = time.time() if now is None else now
    owner = secrets.token_hex(16)
    with transaction(db) as conn:
        conn.execute(
            "UPDATE flow_jobs SET status='failed',reason='lease_retries_exhausted' WHERE status='running' AND lease_until<? AND attempts>=3",
            (now,),
        )
        # Expired leases can be reclaimed; failures are not endlessly retried.
        row = conn.execute(
            """SELECT j.event,j.session,j.model,j.attempts FROM flow_jobs j
            JOIN events e ON e.event_id=j.event
            WHERE j.scope=? AND (j.status='pending' OR (j.status='running' AND j.lease_until<?))
            AND j.attempts<3 ORDER BY e.sequence_no LIMIT 1""",
            (scope, now),
        ).fetchone()
        if not row:
            return None
        event, session, model, attempts = row
        conn.execute(
            "UPDATE flow_jobs SET status='running',owner=?,lease_until=?,attempts=? WHERE scope=? AND event=? AND model=?",
            (owner, now + 600, attempts + 1, scope, event, model),
        )
    return dict(scope=scope, event=event, session=session, model=model, owner=owner)


def finish(db, job, status, reason=""):
    if status not in ("done", "failed", "paused", "pending"):
        raise ValueError("invalid_job_outcome")
    with transaction(db) as conn:
        if status == "pending":
            conn.execute(
                "UPDATE flow_jobs SET attempts=MAX(attempts-1,0) WHERE scope=? AND event=? AND model=? AND owner=? AND status='running'",
                (job["scope"], job["event"], job["model"], job["owner"]),
            )
        changed = conn.execute(
            "UPDATE flow_jobs SET status=?,reason=?,lease_until=0 WHERE scope=? AND event=? AND model=? AND status='running' AND owner=?",
            (status, reason, job["scope"], job["event"], job["model"], job["owner"]),
        ).rowcount
    return changed == 1


def drain(db, scope, *, provider=None, max_jobs=32, lease_factory=None):
    from tooluseproxy.engine.runtime import configuration, session_lock
    from tooluseproxy.engine.judge import CodexSemanticJudge
    from tooluseproxy.engine.property_graph import analyze_properties
    from tooluseproxy.integrations.activation import enabled_workspace_root
    from tooluseproxy.integrations.authority import registered_workspace_authority_lease

    completed = 0
    for _ in range(max_jobs):
        job = claim(db, scope)
        if job is None:
            break
        try:
            config = configuration(Path(db), scope)
            if not config or config.get("background_provenance") is not True:
                finish(db, job, "paused", "background_disabled")
                continue
            with sqlite3.connect(db) as conn:
                lease = (lease_factory or registered_workspace_authority_lease)(
                    Path(db), conn, scope
                )
                with lease as state:
                    if state is not None and state.phase != "active":
                        finish(db, job, "paused", "authority_inactive")
                        continue
                    row = conn.execute(
                        "SELECT canonical_root FROM workspaces WHERE workspace_id=?", (scope,)
                    ).fetchone()
                    if not row or enabled_workspace_root(Path(db), row[0]) != row[0]:
                        finish(db, job, "paused", "workspace_inactive")
                        continue
                    current_model = config.get("model") or "codex_default"
                    if current_model != job["model"]:
                        finish(db, job, "paused", "model_changed")
                        continue
                    started = time.monotonic()
                    judge = provider or CodexSemanticJudge(config.get("model"), timeout=60)

                    def bounded(records):
                        live_config = configuration(Path(db), scope)
                        if not live_config or live_config.get("background_provenance") is not True:
                            raise BackgroundDisabled()
                        if (live_config.get("model") or "codex_default") != job["model"]:
                            raise BackgroundDisabled()
                        if foreground_waiting(db, scope, job["session"]):
                            raise PriorityYield()
                        if (
                            time.monotonic() - started > 480
                            or len(json.dumps(records).encode()) > 512_000
                        ):
                            raise WorkBudget()
                        return judge(records)

                    with session_lock(Path(db), scope, job["session"], background=True):
                        result = analyze_properties(
                            Path(db),
                            scope,
                            job["session"],
                            job["event"],
                            [],
                            bounded,
                            model=job["model"],
                        )
            if result["action"] == "unavailable":
                finish(db, job, "pending", "analysis_incomplete")
                break
            finish(db, job, "done")
            completed += 1
        except BackgroundDisabled:
            finish(db, job, "paused", "configuration_changed")
        except WorkBudget:
            finish(db, job, "pending", "background_budget")
            break
        except PriorityYield:
            finish(db, job, "pending", "foreground_priority")
            break
        except Exception:
            finish(db, job, "failed", "background_analysis_failed")
    return completed


class BackgroundDisabled(Exception):
    pass


class WorkBudget(Exception):
    pass


class PriorityYield(Exception):
    pass


def priority_schema(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS flow_foreground_waiters (scope TEXT NOT NULL,session TEXT NOT NULL,owner TEXT PRIMARY KEY,until REAL NOT NULL)"
    )


def foreground_waiting(db, scope, session):
    with sqlite3.connect(db, timeout=5) as conn:
        priority_schema(conn)
        return bool(
            conn.execute(
                "SELECT 1 FROM flow_foreground_waiters WHERE scope=? AND session=? AND until>?",
                (scope, session, time.time()),
            ).fetchone()
        )


def queue_status(db, scope):
    """Diagnostics must not initialize a database or mutate the queue."""
    if not Path(db).is_file():
        return {}
    conn = sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='flow_jobs'").fetchone():
            return {}
        return dict(conn.execute("SELECT status,COUNT(*) FROM flow_jobs WHERE scope=? GROUP BY status", (scope,)))
    finally:
        conn.close()
