"""Private append-only structural trial store, with idempotent resume.

The caller chooses a NEW/empty dedicated directory. Existing unrelated storage
is refused; this module never discovers or opens a ToolUseProxy runtime DB.
"""

from __future__ import annotations

import json
from datetime import datetime
import os
from pathlib import Path
import sqlite3

from .models import Observation, RecordError, RunSpec, canonical, from_mapping, identifier, timestamp


MARKER = '{"kind":"tooluseproxy_synthetic_flow_lab","schema_version":1}\n'
MAX_BYTES = 1024 * 1024 * 1024
APPLICATION_ID = 0x5455504C


class StoreError(RuntimeError):
    pass


class TrialStore:
    def __init__(self, directory: Path):
        self.directory = directory.absolute()
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise StoreError("unsafe_storage_path")
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if not self.directory.is_dir():
            raise StoreError("unsafe_storage_path")
        marker = self.directory / "flow-lab.json"
        existing = {p.name for p in self.directory.iterdir()}
        if any(p.is_symlink() for p in self.directory.iterdir()):
            raise StoreError("unsafe_storage_path")
        if existing:
            allowed = {"flow-lab.json", "trials.sqlite3", "trials.sqlite3-journal"}
            if not existing <= allowed or not marker.is_file() or marker.is_symlink():
                raise StoreError("unrelated_storage_directory")
            if marker.read_text() != MARKER:
                raise StoreError("storage_kind_mismatch")
        else:
            with marker.open("x", encoding="utf-8") as handle:
                os.chmod(marker, 0o600)
                handle.write(MARKER)
                handle.flush()
                os.fsync(handle.fileno())
        database = self.directory / "trials.sqlite3"
        if database.is_symlink() or (database.exists() and database.stat().st_nlink != 1):
            raise StoreError("unsafe_storage_path")
        existing_database = database.exists()
        self._connection = sqlite3.connect(database, timeout=5, isolation_level=None)
        if existing_database:
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            identity = self._connection.execute("PRAGMA application_id").fetchone()[0]
            tables = {
                row[0] for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if version != 1 or identity != APPLICATION_ID or tables != {
                "lab_run", "lab_observation", "lab_pending"
            }:
                self._connection.close()
                raise StoreError("storage_schema_mismatch")
        os.chmod(database, 0o600)
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS lab_run (
                run_id TEXT PRIMARY KEY, spec TEXT NOT NULL, digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('running','complete','budget_exhausted')),
                ended_at TEXT
            );
            CREATE TABLE IF NOT EXISTS lab_observation (
                sequence_no INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES lab_run(run_id),
                attempt_id TEXT NOT NULL, step_id TEXT NOT NULL UNIQUE,
                tool_use_id TEXT NOT NULL, step_no INTEGER NOT NULL, payload TEXT NOT NULL,
                UNIQUE(run_id, attempt_id, step_no), UNIQUE(run_id, tool_use_id)
            );
            CREATE TABLE IF NOT EXISTS lab_pending (
                step_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES lab_run(run_id),
                attempt_id TEXT NOT NULL, tool_use_id TEXT NOT NULL, step_no INTEGER NOT NULL,
                reserved_at TEXT NOT NULL, UNIQUE(run_id, attempt_id), UNIQUE(run_id, tool_use_id)
            );
        """)
        if not existing_database:
            self._connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            self._connection.execute("PRAGMA user_version=1")

    def close(self) -> None:
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def start(self, spec: RunSpec) -> None:
        existing = self._connection.execute(
            "SELECT spec FROM lab_run WHERE run_id=?", (spec.run_id,)
        ).fetchone()
        if existing:
            if existing[0] != canonical(spec):
                raise StoreError("run_revision_mismatch")
            return
        self._connection.execute(
            "INSERT INTO lab_run VALUES (?,?,?,'running',NULL)",
            (spec.run_id, canonical(spec), spec.digest),
        )

    def append(self, spec: RunSpec, observation: Observation) -> int:
        if observation.run_id != spec.run_id:
            raise StoreError("run_identity_mismatch")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT spec,state FROM lab_run WHERE run_id=?", (spec.run_id,)
            ).fetchone()
            if not row or row[0] != canonical(spec):
                raise StoreError("run_revision_mismatch")
            serialized = canonical(observation)
            duplicate = self._connection.execute(
                "SELECT sequence_no,payload FROM lab_observation WHERE step_id=?",
                (observation.step_id,),
            ).fetchone()
            if duplicate:
                if duplicate[1] != serialized:
                    raise StoreError("observation_identity_conflict")
                self._connection.execute("COMMIT")
                return duplicate[0]
            if row[1] != "running":
                raise StoreError("run_already_finished")
            pending = self._connection.execute(
                "SELECT step_id,tool_use_id,step_no FROM lab_pending "
                "WHERE run_id=? AND attempt_id=?", (spec.run_id, observation.attempt_id),
            ).fetchone()
            if pending and pending != (
                observation.step_id, observation.tool_use_id, observation.step_no
            ):
                raise StoreError("reservation_conflict")
            latest = self._connection.execute(
                "SELECT MAX(step_no) FROM lab_observation WHERE run_id=? AND attempt_id=?",
                (spec.run_id, observation.attempt_id),
            ).fetchone()[0]
            if observation.step_no != (latest or 0) + 1:
                raise StoreError("step_order_mismatch")
            if latest is None:
                attempts = {
                    row[0] for row in self._connection.execute(
                        "SELECT attempt_id FROM lab_observation WHERE run_id=? UNION "
                        "SELECT attempt_id FROM lab_pending WHERE run_id=?",
                        (spec.run_id, spec.run_id),
                    )
                }
                if observation.attempt_id not in attempts and len(attempts) >= spec.max_trials:
                    raise StoreError("trial_budget_exhausted")
            if observation.step_no > spec.max_steps:
                raise StoreError("step_budget_exhausted")
            if sum(p.stat().st_size for p in self.directory.iterdir()) >= MAX_BYTES:
                raise StoreError("storage_budget_exhausted")
            cursor = self._connection.execute(
                "INSERT INTO lab_observation "
                "(run_id,attempt_id,step_id,tool_use_id,step_no,payload) VALUES (?,?,?,?,?,?)",
                (spec.run_id, observation.attempt_id, observation.step_id,
                 observation.tool_use_id, observation.step_no, serialized),
            )
            self._connection.execute(
                "DELETE FROM lab_pending WHERE step_id=?", (observation.step_id,)
            )
            self._connection.execute("COMMIT")
            return cursor.lastrowid
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def reserve(
        self, spec: RunSpec, *, attempt_id: str, step_id: str,
        tool_use_id: str, step_no: int, reserved_at: str,
    ) -> bool:
        """Return True exactly once. False means DO NOT repeat the side effect.

        Pending reservations survive crashes; reconcile with the independent
        receiver before resolving them. Never infer that the operation failed.
        """
        for value in (attempt_id, step_id, tool_use_id):
            identifier(value)
        timestamp(reserved_at)
        if type(step_no) is not int or not 1 <= step_no <= spec.max_steps:
            raise StoreError("step_budget_exhausted")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            run = self._connection.execute(
                "SELECT spec,state FROM lab_run WHERE run_id=?", (spec.run_id,)
            ).fetchone()
            if not run or run[0] != canonical(spec):
                raise StoreError("run_revision_mismatch")
            identity = (spec.run_id, attempt_id, tool_use_id, step_no)
            for table in ("lab_observation", "lab_pending"):
                existing = self._connection.execute(
                    f"SELECT run_id,attempt_id,tool_use_id,step_no FROM {table} WHERE step_id=?",
                    (step_id,),
                ).fetchone()
                if existing:
                    if existing != identity:
                        raise StoreError("reservation_conflict")
                    self._connection.execute("COMMIT")
                    return False
            if run[1] != "running":
                raise StoreError("run_already_finished")
            active = self._connection.execute(
                "SELECT 1 FROM lab_pending WHERE run_id=? AND attempt_id=?",
                (spec.run_id, attempt_id),
            ).fetchone()
            if active:
                raise StoreError("attempt_has_unresolved_operation")
            latest = self._connection.execute(
                "SELECT MAX(step_no) FROM lab_observation WHERE run_id=? AND attempt_id=?",
                (spec.run_id, attempt_id),
            ).fetchone()[0]
            if step_no != (latest or 0) + 1:
                raise StoreError("step_order_mismatch")
            attempts = {
                row[0] for row in self._connection.execute(
                    "SELECT attempt_id FROM lab_observation WHERE run_id=? UNION "
                    "SELECT attempt_id FROM lab_pending WHERE run_id=?", (spec.run_id, spec.run_id),
                )
            }
            if attempt_id not in attempts and len(attempts) >= spec.max_trials:
                raise StoreError("trial_budget_exhausted")
            if sum(p.stat().st_size for p in self.directory.iterdir()) >= MAX_BYTES:
                raise StoreError("storage_budget_exhausted")
            self._connection.execute(
                "INSERT INTO lab_pending VALUES (?,?,?,?,?,?)",
                (step_id, *identity, reserved_at),
            )
            self._connection.execute("COMMIT")
            return True
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def pending(self, spec: RunSpec) -> list[dict]:
        run = self._connection.execute(
            "SELECT spec FROM lab_run WHERE run_id=?", (spec.run_id,)
        ).fetchone()
        if not run or run[0] != canonical(spec):
            raise StoreError("run_revision_mismatch")
        rows = self._connection.execute(
            "SELECT step_id,attempt_id,tool_use_id,step_no,reserved_at "
            "FROM lab_pending WHERE run_id=? ORDER BY reserved_at,step_id", (spec.run_id,),
        )
        return [dict(zip(
            ("step_id", "attempt_id", "tool_use_id", "step_no", "reserved_at"), row,
        )) for row in rows]

    def finish(self, spec: RunSpec, ended_at: str, *, exhausted: bool = False) -> None:
        timestamp(ended_at)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._finish(spec, ended_at, exhausted=exhausted)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _finish(self, spec: RunSpec, ended_at: str, *, exhausted: bool) -> None:
        if self.pending(spec):
            raise StoreError("unresolved_operations")
        state = "budget_exhausted" if exhausted else "complete"
        row = self._connection.execute(
            "SELECT spec,state,ended_at FROM lab_run WHERE run_id=?", (spec.run_id,)
        ).fetchone()
        if not row or row[0] != canonical(spec):
            raise StoreError("run_revision_mismatch")
        if row[1] != "running":
            if row[1:] != (state, ended_at):
                raise StoreError("finish_conflict")
            return
        if datetime.fromisoformat(ended_at) < datetime.fromisoformat(spec.started_at):
            raise StoreError("finish_before_start")
        self._connection.execute(
            "UPDATE lab_run SET state=?,ended_at=? WHERE run_id=?",
            (state, ended_at, spec.run_id),
        )

    def read(self, spec: RunSpec) -> list[Observation]:
        row = self._connection.execute(
            "SELECT spec FROM lab_run WHERE run_id=?", (spec.run_id,)
        ).fetchone()
        if not row or row[0] != canonical(spec):
            raise StoreError("run_revision_mismatch")
        rows = self._connection.execute(
            "SELECT attempt_id,step_id,tool_use_id,step_no,payload "
            "FROM lab_observation WHERE run_id=? ORDER BY sequence_no",
            (spec.run_id,),
        )
        result = []
        last_steps: dict[str, int] = {}
        for row in rows:
            try:
                observation = from_mapping(Observation, json.loads(row[4]))
            except (RecordError, json.JSONDecodeError) as exc:
                raise StoreError("invalid_stored_record") from exc
            if observation.run_id != spec.run_id or row[:4] != (
                observation.attempt_id, observation.step_id, observation.tool_use_id,
                observation.step_no,
            ):
                raise StoreError("invalid_stored_identity")
            if observation.step_no != last_steps.get(observation.attempt_id, 0) + 1:
                raise StoreError("stored_step_gap")
            last_steps[observation.attempt_id] = observation.step_no
            result.append(observation)
        return result

    def summary(self, spec: RunSpec) -> dict:
        observations = self.read(spec)
        row = self._connection.execute(
            "SELECT state FROM lab_run WHERE run_id=?", (spec.run_id,)
        ).fetchone()
        counts: dict[str, int] = {}
        for observation in observations:
            for outcome in observation.outcomes():
                counts[outcome] = counts.get(outcome, 0) + 1
        return {
            "schema_version": 1, "cohort": "synthetic", "state": row[0],
            "observation_count": len(observations),
            "unresolved_count": len(self.pending(spec)),
            "attempt_count": len({o.attempt_id for o in observations}), "outcomes": counts,
            "native_hook_observed_count": sum(o.hook_delivery == "observed" for o in observations),
            "controller_only_count": sum(
                o.hook_delivery == "controller_only" for o in observations
            ),
        }
