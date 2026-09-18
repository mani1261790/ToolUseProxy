from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.branches import Continuation, Transfer
from hook_monitor.evaluation.flow_forecast.metrics import (
    WarningPoint, score_early_warning, score_routes, truth_edges, truth_routes,
)
from hook_monitor.evaluation.flow_forecast.predictions import Forecast, Outcome, Route
from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject as Obj, ObservedStep as Step, freeze_prefix,
)


def branch():
    prefix = freeze_prefix(root_case_id='case', max_sequence_no=1,
                           observations=(Step(1, 'file', 'read', ('source',), ('memory',), 'ok'),),
                           objects=(Obj('source', 'source', 0), Obj('memory', 'bytes', 1)),
                           capabilities=('file', 'http', 'tool_output'), environment_version='v1',
                           source_version='v1', protected_sources=('source',))
    return Continuation(prefix, 'send', 'observe', 'fixed_replay', 'fixed_distribution', 1.0,
                        (Step(2, 'tool_output', 'branch', result='send'),
                         Step(3, 'file', 'encode', ('memory',), ('future-bytes',), 'ok'),
                         Step(4, 'http', 'send', ('future-bytes',), ('receiver',), 'ok')),
                        (Obj('future-bytes', 'bytes', 3), Obj('receiver', 'sink', 4)),
                        (Transfer('source', 'memory', 1, 'copy', 'checked_bytes', 'a' * 64),
                         Transfer('memory', 'future-bytes', 3, 'base64', 'checked_bytes', 'b' * 64),
                         Transfer('future-bytes', 'receiver', 4, 'send', 'receiver', 'c' * 64)),
                        ('source',), (('receiver', 4),), True, 'completed', 'control')


def prediction(item, outcomes, p=1, horizon=4, **kwargs):
    return Forecast(item.prefix.snapshot_digest, item.policy_mode, horizon, 'test-v1', p, outcomes, **kwargs)


def test_future_routes_omit_visible_edges_and_anonymize_future_ids():
    item = branch()
    assert truth_routes(item, 4) == (Route('source', 'memory', ((2, 'base64', 'bytes'), (3, 'send', 'sink'))),)
    expected = truth_routes(item, 4)
    assert len(truth_edges(item, 4)) == 2  # prior source -> memory read is not a future edge
    result = score_routes(prediction(item, (Outcome(expected, 1),)), item)
    assert result['edge_f1'] == 1 and result['joint_top_k_hit']
    assert result['route_coverage'] == 1


def test_partial_future_edges_are_scored_even_before_arrival():
    item = branch()
    assert truth_routes(item, 2) == ()
    assert len(truth_edges(item, 2)) == 1  # encoding has happened; send has not
    forecast = prediction(item, (Outcome((), 1),), p=0, horizon=2)
    result = score_routes(forecast, item)
    assert result['joint_top_k_hit']
    assert result['edge_f1'] == 0


def test_joint_path_probabilities_are_not_multiplied_per_edge():
    item = branch()
    forecast = prediction(item, (Outcome(truth_routes(item, 4), .7), Outcome((), .3)), p=.7)
    assert forecast.protected_probability == .7
    with pytest.raises(ForecastDataError, match='risk_inconsistent'):
        replace(forecast, protected_probability=.49)


def test_missing_candidate_and_unknown_truth_are_separate():
    item = branch()
    forecast = prediction(item, (), p=None, unknown_probability=1)
    result = score_routes(forecast, item)
    assert result['candidate_missing'] and result['edge_f1'] == 0
    stopped = replace(item, observations=item.observations[:1], objects=(),
                      transfers=item.transfers[:1], receiver_arrivals=(), termination='blocked')
    assert score_routes(forecast, stopped)['status'] == 'unknown_truth'
    assert score_routes(forecast, stopped)['edge_f1'] is None


def test_forecast_cannot_be_reused_for_another_prefix_or_condition():
    item = branch()
    forecast = prediction(item, (), p=.5, other_probability=1)
    with pytest.raises(ForecastDataError):
        forecast.validate_for(replace(item.prefix, source_version='v2'), policy_mode='observe', horizon=4)
    with pytest.raises(ForecastDataError):
        forecast.validate_for(item.prefix, policy_mode='enforce', horizon=4)
    with pytest.raises(ForecastDataError):
        prediction(item, (Outcome(truth_routes(item, 4), .8),), p=.8)


def test_only_pre_move_warnings_within_their_horizon_count_as_early():
    item = branch()
    def point(at, horizon=4):
        return WarningPoint('case', 'send', 'observe', at, .9, horizon)
    assert score_early_warning(item, (point(1), point(3)), threshold=.5)['lead_steps'] == 3
    late = score_early_warning(item, (point(4),), threshold=.5)
    assert not late['detected_early'] and late['late_alarm']
    outside = score_early_warning(item, (point(1, 1),), threshold=.5)
    assert not outside['detected_early'] and outside['out_of_horizon_alarms'] == 1
    with pytest.raises(ForecastDataError):
        score_early_warning(item, (point(3), point(1)), threshold=.5)
    with pytest.raises(ForecastDataError):
        score_early_warning(item, (replace(point(1), branch_id='other'),), threshold=.5)
