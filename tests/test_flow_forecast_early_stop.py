from dataclasses import asdict, replace

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.early_stop import assess
from hook_monitor.evaluation.flow_forecast.predictions import Forecast, Outcome, Route
from research.flow_forecast.model import ALGORITHM
from research.flow_forecast.recording.contracts import Current
from research.flow_forecast.recording.worker import checked_result
from test_flow_forecast_recording import request as fixture_request


def ready():
    request = fixture_request()
    # Deliberate positive unit fixture. This is not a trained model effectiveness
    # result; the F03 enforce model may legitimately abstain on these traces.
    source = request.prefix.protected_sources[0]
    forecast = Forecast(request.prefix.snapshot_digest, 'enforce', 4,
                        ALGORITHM + '-' + request.model_digest[:12], 1,
                        (Outcome((Route(source, source, ((1, 'send', 'sink'),)),), 1),))
    result = checked_result({'status': 'recorded', 'model_digest': request.model_digest, 'forecast': asdict(forecast)}, request)
    record = {'request_id': request.request_id, 'status': 'recorded', 'result': result}
    return request, record, Current(request.binding, request.model_digest)


def evaluate(request, record, current, **changes):
    args = {'now': 1001, 'existing_block': False, 'experiment_enabled': True, 'threshold': .5}
    return assess(request, record, current, **(args | changes))


def test_experiment_is_off_by_default_and_never_relaxes_existing_block():
    request, record, current = ready()
    result = assess(request, record, current, now=1001, existing_block=False)
    assert not result.stop and result.reason == 'experiment_disabled'
    for enabled in (False, True):
        result = assess(None, None, None, now=1001, existing_block=True, experiment_enabled=enabled)
        assert result.stop and result.existing_block and not result.additional_stop


def test_only_bound_current_prediction_can_add_a_stop():
    request, record, current = ready()
    result = evaluate(request, record, current, threshold=0)
    assert result.stop and result.additional_stop and not result.existing_block
    disabled = evaluate(request, record, current, experiment_enabled=False)
    assert not disabled.stop
    assert evaluate(request, record, current, now=1030).reason == 'expired'
    assert evaluate(request, record, current, threshold=None).reason == 'threshold_unavailable'
    for field, value in [('session_id', 'another'), ('candidate_id', 'other-operation'),
                         ('protection_digest', 'f' * 64), ('policy_digest', 'f' * 64),
                         ('project_generation', 2), ('observed_sequence', 3)]:
        changed = Current(replace(current.binding, **{field: value}), current.model_digest)
        assert not evaluate(request, record, changed, threshold=0).stop
    assert evaluate(request, record, replace(current, model_digest='f' * 64)).reason == 'model_version_changed'


def test_missing_or_rebound_history_cannot_stop_a_different_operation():
    request, record, current = ready()
    assert evaluate(request, None, current).reason == 'prediction_unavailable'
    rebound = dict(record, request_id='another')
    assert evaluate(request, rebound, current).reason == 'prediction_binding_mismatch'
    rebound = dict(record, result=dict(record['result'], binding=asdict(replace(request.binding, candidate_id='other'))))
    assert evaluate(request, rebound, current).reason == 'prediction_binding_mismatch'


def test_unknown_is_not_a_zero_or_a_high_confidence_stop():
    request, record, current = ready()
    forecast = dict(record['result']['forecast'], outcomes=[], other_probability=0,
                    unknown_probability=1, protected_probability=None)
    record = dict(record, result=dict(record['result'], forecast=forecast))
    result = evaluate(request, record, current, threshold=0)
    assert not result.stop and result.reason == 'prediction_unknown'
    forecast['protected_probability'] = 1
    assert evaluate(request, record, current).reason == 'prediction_unknown'
    forecast['protected_probability'] = 2
    assert evaluate(request, record, current).reason == 'invalid_prediction'


@pytest.mark.parametrize('threshold', [-1, 2, True, float('nan'), float('inf')])
def test_invalid_threshold_is_rejected(threshold):
    request, record, current = ready()
    with pytest.raises(ForecastDataError, match='invalid_experiment_threshold'):
        evaluate(request, record, current, threshold=threshold)
