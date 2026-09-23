"""Content-free phase timings. Diagnostics never change a protection decision."""

from contextlib import contextmanager
import sqlite3
import time


@contextmanager
def measure(db, event, phase):
    started = time.monotonic_ns()
    outcome = "completed"
    try:
        yield
    except BaseException:
        outcome = "failed"
        raise
    finally:
        duration = (time.monotonic_ns() - started) / 1_000_000
        try:
            with sqlite3.connect(db, timeout=0.1) as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS flow_phase_timings (
                    id INTEGER PRIMARY KEY, event TEXT NOT NULL, phase TEXT NOT NULL,
                    duration_ms REAL NOT NULL, outcome TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS flow_timing_event ON flow_phase_timings(event,id)"
                )
                conn.execute(
                    "INSERT INTO flow_phase_timings(event,phase,duration_ms,outcome) VALUES (?,?,?,?)",
                    (event, phase, duration, outcome),
                )
        except sqlite3.Error:
            pass


def measured(db, event, phase, operation):
    def run(*args, **kwargs):
        with measure(db, event, phase):
            return operation(*args, **kwargs)

    return run
