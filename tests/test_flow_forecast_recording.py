from dataclasses import asdict, replace
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.recording.contracts import Binding, Request, parse_request
from test_flow_forecast_sequence_model import find
from test_flow_forecast_baselines import dataset


def request():
    prefix = find(dataset(), cut=2).prefix
    binding = Binding('workspace', 'session', 'event', 'call', 'a' * 64, 'b' * 64,
                      'c' * 64, prefix.snapshot_digest, 2, 1)
    return Request(binding, prefix, 'd' * 64, 1000)


def test_recording_request_roundtrip_and_exact_expiry_boundary():
    item = request()
    restored = parse_request(json.loads(json.dumps(asdict(item))))
    assert restored == item and restored.request_id == item.request_id
    assert item.validity(item.binding, item.model_digest, 1000) == 'current'
    assert item.validity(item.binding, item.model_digest, 1029.99) == 'current'
    assert item.validity(item.binding, item.model_digest, 1030) == 'expired'
    assert item.validity(item.binding, item.model_digest, 999) == 'clock_reversed'


@pytest.mark.parametrize('field,value,reason', [
    ('workspace_id', 'another', 'different_workspace'),
    ('session_id', 'another', 'different_session'),
    ('project_generation', 2, 'project_generation_changed'),
    ('event_id', 'new-event', 'input_version_changed'),
    ('candidate_id', 'other-call', 'input_version_changed'),
    ('candidate_digest', 'e' * 64, 'input_version_changed'),
    ('protection_digest', 'e' * 64, 'input_version_changed'),
    ('policy_digest', 'e' * 64, 'input_version_changed'),
    ('prefix_digest', 'e' * 64, 'input_version_changed'),
    ('observed_sequence', 3, 'input_version_changed'),
])
def test_each_binding_dimension_invalidates_an_old_prediction(field, value, reason):
    item = request()
    assert item.validity(replace(item.binding, **{field: value}), item.model_digest, 1001) == reason


def test_model_change_and_unbound_prefix_are_rejected():
    item = request()
    assert item.validity(item.binding, 'f' * 64, 1001) == 'model_version_changed'
    with pytest.raises(ForecastDataError, match='prefix_mismatch'):
        replace(item, prefix=replace(item.prefix, source_version='changed'))


def test_request_does_not_accept_policy_overrides_or_unknown_schema():
    value = json.loads(json.dumps(asdict(request())))
    for field, content in [('allow', True), ('command', 'anything'), ('policy_decision', 'allow')]:
        with pytest.raises(ForecastDataError):
            parse_request({**value, field: content})
    with pytest.raises(ForecastDataError):
        parse_request({**value, 'schema': 2})
    with pytest.raises(ForecastDataError):
        replace(request(), ttl_seconds=3600)
