"""Capacity fixtures are mechanical copies, not independent research samples."""
from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.baselines import fit_baseline
from hook_monitor.evaluation.flow_forecast.dataset import MAX_BRANCHES, assemble, read_dataset, write_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_forecast.protocol import load_protocol
from research.flow_forecast.model import fit
from test_flow_forecast_dataset import branches


def capacity_dataset(roots):
    base = branches()
    values = []
    for index in range(roots):
        prefix = replace(base[0].prefix, root_case_id=f'capacity-{index}', source_version=f'copy-{index}')
        values.extend(replace(branch, prefix=prefix) for branch in base)
    return assemble(tuple(values))


def test_minimum_population_size_can_roundtrip_without_changing_batch_limits(tmp_path):
    protocol = load_protocol()
    roots = sum(protocol[key] for key in ('minimum_training_roots', 'minimum_calibration_normal_roots',
                                         'minimum_test_normal_roots', 'minimum_test_positive_roots'))
    data = capacity_dataset(roots)
    assert roots == 520 and len(data.branches) == 2080
    write_dataset(data, tmp_path / 'dataset')
    assert read_dataset(tmp_path / 'dataset') == data
    assert protocol['maximum_trial_attempts_per_explicit_batch'] == 20
    assert protocol['maximum_seconds_per_explicit_batch'] == 1800
    assert protocol['maximum_storage_bytes_per_explicit_batch'] == 1024 ** 3
    assert protocol['automatic_batch_extension'] is False


def test_record_count_is_still_bounded():
    with pytest.raises(ForecastDataError, match='invalid_dataset'):
        assemble((branches()[0],) * (MAX_BRANCHES + 1))


def test_sequence_model_root_capacity_matches_group_split_bound():
    model = fit(capacity_dataset(10))
    # Only exercises model representation, never claims training on these roots.
    roots = tuple(f'capacity-{index:05d}' for index in range(3200))
    assert len(replace(model, training_roots=roots).training_roots) == 3200
    with pytest.raises(ForecastDataError, match='invalid_sequence_model'):
        replace(model, training_roots=tuple(f'capacity-{index:05d}' for index in range(10001)))


@pytest.mark.parametrize('kind', ['frequency', 'risk_only', 'one_step'])
def test_baseline_obeys_budget_during_fitting(kind):
    data = capacity_dataset(10)
    checks = []
    def exhausted():
        checks.append(True)
        if len(checks) == 3:
            raise ForecastDataError('synthetic_budget_exhausted')
    with pytest.raises(ForecastDataError, match='synthetic_budget_exhausted'):
        fit_baseline(data, kind, check_budget=exhausted)
    assert len(checks) == 3


def test_optimizer_checks_budget_before_finishing_all_epochs(monkeypatch):
    from hook_monitor.evaluation.flow_forecast import baselines
    data = capacity_dataset(10)
    sigmoid = baselines._sigmoid
    calls = []
    def observed(value):
        calls.append(True)
        return sigmoid(value)
    def exhausted_after_optimization_begins():
        if calls:
            raise ForecastDataError('optimizer_budget_exhausted')
    monkeypatch.setattr(baselines, '_sigmoid', observed)
    with pytest.raises(ForecastDataError, match='optimizer_budget_exhausted'):
        fit_baseline(data, 'risk_only', check_budget=exhausted_after_optimization_begins)
    assert 0 < len(calls) <= len(data.branches)


def test_more_records_do_not_relax_artifact_byte_limit(tmp_path, monkeypatch):
    from hook_monitor.evaluation.flow_forecast import dataset as module
    data = capacity_dataset(10)
    monkeypatch.setattr(module, 'MAX_ARTIFACT_BYTES', 100)
    with pytest.raises(ForecastDataError, match='dataset_size_exceeded'):
        write_dataset(data, tmp_path / 'too-large')
    assert not (tmp_path / 'too-large').exists()
