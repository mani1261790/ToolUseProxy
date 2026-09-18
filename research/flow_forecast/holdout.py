"""Durable research holdout lifecycle. This ledger is not a trust boundary."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError

APPLICATION_ID = 0x484F4C44
SCHEMA = 1
MAX_HOLDOUTS = 1000


def _sha(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ForecastDataError('invalid_holdout_digest')
    return value


def _run(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{32}', value) is None:
        raise ForecastDataError('invalid_holdout_run_id')
    return value


def _now():
    return datetime.now(timezone.utc).isoformat()


class HoldoutLedger:
    """A first reservation consumes the holdout even if evaluation crashes.

    No reset or retry-to-unused operation exists. Filesystem owners can still
    replace this database; independent custody/provenance remains necessary.
    """

    @staticmethod
    def create(path: Path):
        path = Path(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        connection = sqlite3.connect(path)
        try:
            connection.executescript(f'''
                PRAGMA application_id={APPLICATION_ID};
                PRAGMA user_version={SCHEMA};
                CREATE TABLE holdouts (
                    dataset_sha TEXT PRIMARY KEY,
                    manifest_sha TEXT NOT NULL,
                    split_sha TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('sealed','opened','retired')),
                    sealed_at TEXT NOT NULL,
                    run_id TEXT UNIQUE,
                    plan_sha TEXT,
                    model_sha TEXT,
                    evaluator_sha TEXT,
                    opened_at TEXT,
                    report_sha TEXT,
                    completed_at TEXT,
                    retired_at TEXT,
                    retirement_reason TEXT
                );
            ''')
        finally:
            connection.close()
        return HoldoutLedger(path)

    def __init__(self, path: Path):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ForecastDataError('holdout_ledger_unavailable')
        self.path = path.absolute()
        # Validate immediately; never migrate or initialize an existing database.
        with self._connection():
            pass

    @contextmanager
    def _connection(self):
        if self.path.is_symlink():
            raise ForecastDataError('holdout_ledger_unavailable')
        connection = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        try:
            if (connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or connection.execute('PRAGMA user_version').fetchone()[0] != SCHEMA):
                raise ForecastDataError('invalid_holdout_ledger')
            connection.execute('PRAGMA max_page_count=4096')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('BEGIN IMMEDIATE')
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def seal(self, *, dataset_sha, manifest_sha, split_sha):
        values = tuple(_sha(value) for value in (dataset_sha, manifest_sha, split_sha))
        with self._connection() as connection:
            if connection.execute('SELECT COUNT(*) FROM holdouts').fetchone()[0] >= MAX_HOLDOUTS:
                raise ForecastDataError('holdout_ledger_capacity')
            if connection.execute('SELECT 1 FROM holdouts WHERE dataset_sha=?', (dataset_sha,)).fetchone():
                raise ForecastDataError('holdout_already_registered')
            connection.execute(
                "INSERT INTO holdouts(dataset_sha,manifest_sha,split_sha,state,sealed_at) "
                "VALUES(?,?,?,'sealed',?)", (*values, _now()))

    def reserve(self, *, dataset_sha, manifest_sha, split_sha, run_id,
                plan_sha, model_sha, evaluator_sha):
        for value in (dataset_sha, manifest_sha, split_sha, plan_sha, model_sha, evaluator_sha):
            _sha(value)
        _run(run_id)
        with self._connection() as connection:
            row = connection.execute('SELECT * FROM holdouts WHERE dataset_sha=?', (dataset_sha,)).fetchone()
            if row is None:
                raise ForecastDataError('holdout_not_sealed')
            if (row['manifest_sha'], row['split_sha']) != (manifest_sha, split_sha):
                raise ForecastDataError('holdout_seal_mismatch')
            if row['state'] != 'sealed':
                raise ForecastDataError('holdout_already_consumed')
            if connection.execute('SELECT 1 FROM holdouts WHERE run_id=?', (run_id,)).fetchone():
                raise ForecastDataError('holdout_run_id_reused')
            connection.execute(
                "UPDATE holdouts SET state='opened',run_id=?,plan_sha=?,model_sha=?,"
                "evaluator_sha=?,opened_at=? WHERE dataset_sha=?",
                (run_id, plan_sha, model_sha, evaluator_sha, _now(), dataset_sha))
        return self.status(dataset_sha)

    def finish(self, *, dataset_sha, run_id, report_sha):
        _sha(dataset_sha)
        _sha(report_sha)
        _run(run_id)
        with self._connection() as connection:
            result = connection.execute(
                "UPDATE holdouts SET report_sha=?,completed_at=? WHERE dataset_sha=? "
                "AND run_id=? AND state='opened' AND report_sha IS NULL",
                (report_sha, _now(), dataset_sha, run_id))
            if result.rowcount != 1:
                raise ForecastDataError('holdout_completion_mismatch')

    def retire(self, *, dataset_sha, reason):
        _sha(dataset_sha)
        if reason not in {'tuning_after_open', 'contaminated', 'abandoned'}:
            raise ForecastDataError('invalid_holdout_retirement_reason')
        with self._connection() as connection:
            result = connection.execute(
                "UPDATE holdouts SET state='retired',retired_at=?,retirement_reason=? "
                "WHERE dataset_sha=? AND state!='retired'", (_now(), reason, dataset_sha))
            if result.rowcount != 1:
                raise ForecastDataError('holdout_retirement_mismatch')

    def status(self, dataset_sha):
        _sha(dataset_sha)
        with self._connection() as connection:
            row = connection.execute('SELECT * FROM holdouts WHERE dataset_sha=?', (dataset_sha,)).fetchone()
        if row is None:
            raise ForecastDataError('holdout_not_sealed')
        return {**dict(row), 'scope': 'local_lifecycle_record_only',
                'independent_custody_verified': False, 'prior_external_use_verified': False}
