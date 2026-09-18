"""Mechanical partition fixtures do not demonstrate research independence."""
from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import compare_holdout, partition_bundle
from research.flow_forecast.holdout import HoldoutLedger
from test_flow_forecast_dataset import branches


def fixture_dataset():
    # Distinct snapshots here only exercise grouping/IO, not independent tasks.
    selected = {}
    base = branches()
    for index in range(200):
        prefix = replace(base[0].prefix, root_case_id=f'fixture-{index}', source_version=f'fixture-{index}')
        values = tuple(replace(b, prefix=prefix) for b in base)
        part = assemble(values).split.partition(prefix)
        selected.setdefault(part, values)
        if len(selected) == 3:
            break
    assert len(selected) == 3
    return assemble(tuple(b for group in selected.values() for b in group))


def bundle(tmp_path):
    directory = tmp_path / 'bundle'
    manifest = partition_bundle.write_bundle(fixture_dataset(), directory)
    return directory, manifest


def test_preparation_never_reads_test_files(tmp_path, monkeypatch):
    directory, manifest = bundle(tmp_path)
    # Even a completely missing test directory must not affect preparation.
    (directory / 'test').rename(tmp_path / 'sealed-away')
    plan = compare_holdout.prepare(directory)
    assert plan['bundle_sha'] == manifest['bundle_sha']
    development = partition_bundle.read_development(directory, manifest)
    assert {row[2] for row in development.split.assignments} == {'train', 'calibration'}


def test_opening_is_committed_before_test_read_and_failure_is_consumed(tmp_path, monkeypatch):
    directory, manifest = bundle(tmp_path)
    ledger = HoldoutLedger.create(tmp_path / 'ledger.db')
    seal = manifest['partitions']['test']
    ledger.seal(**seal)
    plan = compare_holdout.prepare(directory)
    real_read = compare_holdout.read_partition

    def fail_on_test(path, metadata, name):
        assert name == 'test'
        assert HoldoutLedger(ledger.path).status(seal['dataset_sha'])['state'] == 'opened'
        raise ForecastDataError('simulated_read_failure')

    monkeypatch.setattr(compare_holdout, 'read_partition', fail_on_test)
    with pytest.raises(ForecastDataError, match='simulated_read_failure'):
        compare_holdout.evaluate_once(directory, plan, ledger)
    monkeypatch.setattr(compare_holdout, 'read_partition', real_read)
    with pytest.raises(ForecastDataError, match='already_consumed'):
        compare_holdout.evaluate_once(directory, plan, ledger)


def test_plan_mismatch_does_not_consume_and_success_records_report(tmp_path):
    directory, manifest = bundle(tmp_path)
    ledger = HoldoutLedger.create(tmp_path / 'ledger.db')
    seal = manifest['partitions']['test']
    ledger.seal(**seal)
    plan = compare_holdout.prepare(directory)
    with pytest.raises(ForecastDataError, match='plan_mismatch'):
        compare_holdout.evaluate_once(directory, {**plan, 'model_sha': '0' * 64}, ledger)
    assert ledger.status(seal['dataset_sha'])['state'] == 'sealed'
    result = compare_holdout.evaluate_once(directory, plan, ledger)
    assert ledger.status(seal['dataset_sha'])['report_sha']
    assert result['holdout']['reservation']['prior_external_use_verified'] is False
    assert result['generalization']['test_prior_use'] == 'conversion_from_accessible_dataset'
    assert result['acceptance']['status'] != 'passed'


def test_tampered_partition_manifest_and_symlink_rejected(tmp_path):
    directory, manifest = bundle(tmp_path)
    (directory / 'test' / 'manifest.json').write_text('{}')
    with pytest.raises(ForecastDataError, match='manifest_mismatch'):
        partition_bundle.read_partition(directory, manifest, 'test')
    (directory / 'calibration').rename(tmp_path / 'elsewhere')
    (directory / 'calibration').symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(ForecastDataError, match='partition_directory'):
        partition_bundle.read_development(directory, manifest)


def test_cli_lifecycle_records_retirement(tmp_path):
    directory, manifest = bundle(tmp_path)
    ledger_path = tmp_path / 'ledger.db'
    plan_path, report_path = tmp_path / 'plan.json', tmp_path / 'report.json'
    compare_holdout.main(['create-ledger', '--ledger', str(ledger_path)])
    common = ['--bundle', str(directory), '--ledger', str(ledger_path)]
    compare_holdout.main(['seal', *common])
    compare_holdout.main(['prepare', '--bundle', str(directory), '--output', str(plan_path)])
    compare_holdout.main(['evaluate', *common, '--plan', str(plan_path), '--output', str(report_path)])
    from hook_monitor.evaluation.flow_forecast.prefix import digest
    import json
    ledger = HoldoutLedger(ledger_path)
    state = ledger.status(manifest['partitions']['test']['dataset_sha'])
    assert state['report_sha'] == digest(json.loads(report_path.read_text()))
    compare_holdout.main(['retire', *common, '--reason', 'tuning_after_open'])
    assert ledger.status(state['dataset_sha'])['state'] == 'retired'
    with pytest.raises(SystemExit):
        compare_holdout.main(['evaluate', *common, '--plan', str(plan_path), '--output', str(report_path)])


def test_group_recombination_rejects_shared_snapshot_crossing_partitions():
    dataset = fixture_dataset()
    groups = {name: partition_bundle._subset(dataset, {name}) for name in ('train', 'test')}
    train, test = groups['train'], groups['test']
    # A forged split collection with identical snapshots still must fail at combine.
    shared = replace(train.prefixes[0], root_case_id=test.prefixes[0].root_case_id)
    changed = assemble(tuple(replace(b, prefix=shared) for b in test.branches))
    assert {row[2] for row in changed.split.assignments} == {'test'}
    with pytest.raises(ForecastDataError, match='cross_partition_group'):
        partition_bundle.combine((train, changed))
