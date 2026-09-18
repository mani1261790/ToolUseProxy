from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.holdout import HoldoutLedger

SEAL = dict(dataset_sha='a' * 64, manifest_sha='b' * 64, split_sha='c' * 64)
OPEN = dict(**SEAL, run_id='1' * 32, plan_sha='d' * 64, model_sha='e' * 64, evaluator_sha='f' * 64)


def sealed(tmp_path):
    ledger = HoldoutLedger.create(tmp_path / 'holdouts.db')
    ledger.seal(**SEAL)
    return ledger


def test_first_reservation_survives_crash_and_cannot_be_reset(tmp_path):
    ledger = sealed(tmp_path)
    ledger.reserve(**OPEN)
    reopened = HoldoutLedger(ledger.path)
    status = reopened.status(SEAL['dataset_sha'])
    assert status['state'] == 'opened'
    assert status['report_sha'] is None
    assert status['prior_external_use_verified'] is False
    with pytest.raises(ForecastDataError, match='already_consumed'):
        reopened.reserve(**{**OPEN, 'run_id': '2' * 32})
    with pytest.raises(ForecastDataError, match='already_registered'):
        reopened.seal(**SEAL)


def test_concurrent_reservations_only_one_wins(tmp_path):
    ledger = sealed(tmp_path)
    def reserve(number):
        try:
            HoldoutLedger(ledger.path).reserve(**{**OPEN, 'run_id': str(number) * 32})
            return 'opened'
        except ForecastDataError as error:
            return str(error)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, (1, 2)))
    assert sorted(results) == ['holdout_already_consumed', 'opened']


def test_seal_mismatch_does_not_consume_and_finish_binds_run(tmp_path):
    ledger = sealed(tmp_path)
    with pytest.raises(ForecastDataError, match='seal_mismatch'):
        ledger.reserve(**{**OPEN, 'manifest_sha': '0' * 64})
    assert ledger.status(SEAL['dataset_sha'])['state'] == 'sealed'
    ledger.reserve(**OPEN)
    with pytest.raises(ForecastDataError, match='completion_mismatch'):
        ledger.finish(dataset_sha=SEAL['dataset_sha'], run_id='2' * 32, report_sha='0' * 64)
    ledger.finish(dataset_sha=SEAL['dataset_sha'], run_id=OPEN['run_id'], report_sha='0' * 64)
    ledger.retire(dataset_sha=SEAL['dataset_sha'], reason='tuning_after_open')
    assert ledger.status(SEAL['dataset_sha'])['state'] == 'retired'
    with pytest.raises(ForecastDataError, match='already_consumed'):
        ledger.reserve(**OPEN)


def test_missing_wrong_or_linked_database_not_created_or_migrated(tmp_path):
    missing = tmp_path / 'missing.db'
    with pytest.raises(ForecastDataError):
        HoldoutLedger(missing)
    assert not missing.exists()
    with sqlite3.connect(missing) as connection:
        connection.execute('CREATE TABLE other(value)')
    with pytest.raises(ForecastDataError, match='invalid_holdout_ledger'):
        HoldoutLedger(missing)
    with pytest.raises(FileExistsError):
        HoldoutLedger.create(missing)
    linked = tmp_path / 'link.db'
    linked.symlink_to(missing)
    with pytest.raises(ForecastDataError):
        HoldoutLedger(linked)
