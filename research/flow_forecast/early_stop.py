"""Additional stopping for artificial comparisons only; no Hook or execution API.

The experiment switch is not administrator authorization or evidence that F04
passed. Results never permit an operation or override an existing block.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, identifier
from .recording.contracts import Current, Request
from .recording.worker import checked_result


@dataclass(frozen=True)
class StopAssessment:
    existing_block: bool
    additional_stop: bool
    reason: str

    def __post_init__(self):
        if type(self.existing_block) is not bool or type(self.additional_stop) is not bool:
            raise ForecastDataError('invalid_stop_flags')
        identifier(self.reason)

    @property
    def stop(self):
        return self.existing_block or self.additional_stop


def assess(request: Request, record: dict | None, current: Current, *, now: float,
           existing_block: bool, experiment_enabled=False, threshold=None) -> StopAssessment:
    """Evaluate at the operation boundary using fresh state supplied by the runner.

    Disabling the experiment immediately removes *additional* stopping only.
    Expired/mismatched history cannot authorize stopping a different operation.
    The caller still applies the existing detector independently.
    """
    if type(existing_block) is not bool:
        raise ForecastDataError('invalid_existing_block')
    if existing_block:
        return StopAssessment(True, False, 'existing_block_preserved')
    if type(experiment_enabled) is not bool:
        raise ForecastDataError('invalid_experiment_switch')
    if not experiment_enabled:
        return StopAssessment(False, False, 'experiment_disabled')
    if threshold is None:
        return StopAssessment(False, False, 'threshold_unavailable')
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ForecastDataError('invalid_experiment_threshold')
    if type(request) is not Request or type(current) is not Current:
        raise ForecastDataError('invalid_stop_input')
    if request.input_scope != 'synthetic':
        return StopAssessment(False, False, 'out_of_domain')
    if request.policy_mode != 'enforce':
        return StopAssessment(False, False, 'policy_mode_mismatch')
    validity = request.validity(current.binding, current.model_digest, now)
    if validity != 'current':
        return StopAssessment(False, False, validity)
    if not isinstance(record, dict) or record.get('status') != 'recorded':
        return StopAssessment(False, False, 'prediction_unavailable')
    result = record.get('result')
    if (record.get('request_id') != request.request_id or not isinstance(result, dict)
            or set(result) != {'request_id', 'binding', 'model_digest', 'forecast', 'record_only'}
            or result['request_id'] != request.request_id or result['binding'] != asdict(request.binding)
            or result['model_digest'] != current.model_digest or result['record_only'] is not True):
        return StopAssessment(False, False, 'prediction_binding_mismatch')
    try:
        checked = checked_result({'status': 'recorded', 'model_digest': result['model_digest'],
                                  'forecast': result['forecast']}, request)
    except ForecastDataError:
        return StopAssessment(False, False, 'invalid_prediction')
    probability = checked['forecast']['protected_probability']
    if (probability is None or checked['forecast']['unknown_probability'] > 0
            or checked['forecast']['other_probability'] > 0):
        return StopAssessment(False, False, 'prediction_unknown')
    if probability >= threshold:
        return StopAssessment(False, True, 'experimental_threshold_reached')
    return StopAssessment(False, False, 'experimental_threshold_not_reached')
