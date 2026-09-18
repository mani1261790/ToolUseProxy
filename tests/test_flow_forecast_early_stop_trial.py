from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from hook_monitor.evaluation.flow_lab.storage import TrialStore
from research.flow_forecast.early_stop import StopAssessment
from research.flow_forecast.early_stop_trial import compare_trials, run_trial
from test_flow_lab_runner import FakeTransport, spec


class Transport(FakeTransport):
    def prepare(self, step_id, **kwargs):
        self.step_id = step_id
        return super().prepare(step_id, **kwargs)

    def guard(self, *args, **kwargs):
        return 'allow'

    def records(self):
        return [{'step_id': self.step_id, 'protected': self.source == 'protected'}] if self.sent else []


def test_pair_measures_completion_cost_and_receiver_reduction(tmp_path):
    transport, run = Transport(), spec()
    rows = []
    with TrialStore(tmp_path / 'lab') as store:
        store.start(run)
        for source in ('public', 'protected'):
            for variant in ('baseline', 'forecast'):
                rows.append(run_trial(transport, store, run, case_id=source, source=source, variant=variant,
                                      gate=(lambda **kwargs: StopAssessment(False, True, 'fixture_stop')) if variant == 'forecast' else None))
        assert store.pending(run) == []
    report = compare_trials(tuple(rows))
    assert report['normal_completion']['paired_change'] == -1
    assert report['protected_arrival']['paired_change'] == -1
    assert report['additional_stops'] == 2
    assert report['stop_delivery_conflicts'] == 0
    assert not report['product_activation_authorized']
    # The original allow remains visible; it is not relabelled as detector deny.
    assert all(row.observation.decision == 'allow' for row in rows)


def test_prediction_failure_and_disable_preserve_existing_deny(tmp_path):
    transport, run = Transport(), spec()
    transport.guard = lambda *args, **kwargs: 'deny'
    with TrialStore(tmp_path / 'lab') as store:
        store.start(run)
        def broken(**kwargs):
            raise ValueError('synthetic prediction failed')
        for gate in (broken, lambda **kw: StopAssessment(True, False, 'experiment_disabled'),
                     lambda **kw: StopAssessment(False, False, 'incorrect_existing_flag')):
            row = run_trial(transport, store, run, case_id='case', source='protected', variant='forecast', gate=gate)
            assert row.observation.process_started == 'no'
            assert row.observation.protected_arrival == 'no'
            assert row.assessment.existing_block
            assert not transport.sent


def test_interruption_keeps_pending_reservation_and_never_sends(tmp_path):
    transport, run = Transport(), spec()
    def interrupted(**kwargs):
        raise KeyboardInterrupt
    with TrialStore(tmp_path / 'lab') as store:
        store.start(run)
        with pytest.raises(KeyboardInterrupt):
            run_trial(transport, store, run, case_id='case', source='public', variant='forecast', gate=interrupted)
        assert len(store.pending(run)) == 1
        assert store.read(run) == [] and not transport.sent


def test_unknown_receiver_is_not_zero_leakage_and_unmatched_pairs_fail(tmp_path):
    transport, run = Transport(), spec()
    with TrialStore(tmp_path / 'lab') as store:
        store.start(run)
        baseline = run_trial(transport, store, run, case_id='case', source='protected')
        transport.down = True
        forecast = run_trial(transport, store, run, case_id='case', source='protected', variant='forecast')
    report = compare_trials((baseline, forecast))
    assert report['protected_arrival']['unknown_pairs'] == 1
    assert report['protected_arrival']['forecast_rate'] is None
    assert report['normal_completion']['forecast_rate'] is None
    with pytest.raises(ForecastDataError, match='unpaired_trial'):
        compare_trials((baseline,))
    with pytest.raises(ForecastDataError, match='conditions_mismatch'):
        compare_trials((baseline, replace(forecast, encoding='base64')))


def test_explicit_trial_budget_is_not_extended(tmp_path):
    from hook_monitor.evaluation.flow_lab.preflight import LabError
    transport, run = Transport(), replace(spec(), max_trials=1)
    with TrialStore(tmp_path / 'lab') as store:
        store.start(run)
        run_trial(transport, store, run, case_id='case', source='public')
        with pytest.raises(LabError, match='budget_exhausted'):
            run_trial(transport, store, run, case_id='case', source='public', variant='forecast')
        assert store.trial_count() == 1
