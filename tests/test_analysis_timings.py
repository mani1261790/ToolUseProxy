import sqlite3

import pytest

from tooluseproxy.engine.timing import measure


def test_failure_is_timed_without_persisting_exception_contents(tmp_path):
    db = tmp_path / "events.db"
    with pytest.raises(ValueError, match="private-payload"):
        with measure(db, "event-1", "semantic_model"):
            raise ValueError("private-payload")
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT event,phase,outcome,duration_ms FROM flow_phase_timings"
        ).fetchone()
        assert row[:3] == ("event-1", "semantic_model", "failed")
        assert row[3] >= 0
        assert "private-payload" not in "\n".join(conn.iterdump())


def test_missing_diagnostic_storage_does_not_change_result(tmp_path):
    with measure(tmp_path / "missing" / "db", "event", "resolve"):
        result = "actual-decision"
    assert result == "actual-decision"
