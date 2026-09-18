"""Estimate bounded collection work; never start trials or certify independence."""
from __future__ import annotations

import argparse
import json
import math

from hook_monitor.evaluation.flow_forecast.protocol import PROTOCOL_SHA256, load_protocol


def plan(*, attempts_per_root: int, controls_per_batch: int, seconds_per_attempt: float) -> dict:
    protocol = load_protocol()
    limit = protocol['maximum_trial_attempts_per_explicit_batch']
    if type(attempts_per_root) is not int or not 1 <= attempts_per_root <= limit:
        raise ValueError('attempts_per_root must be between 1 and the batch attempt limit')
    if type(controls_per_batch) is not int or not 0 <= controls_per_batch < limit:
        raise ValueError('controls_per_batch must leave room for a trial')
    if (type(seconds_per_attempt) not in (int, float)
            or not math.isfinite(seconds_per_attempt) or seconds_per_attempt <= 0):
        raise ValueError('seconds_per_attempt must be positive and finite')
    seconds_limit = protocol['maximum_seconds_per_explicit_batch']
    time_capacity = (limit if seconds_per_attempt <= seconds_limit / limit
                     else math.floor(seconds_limit / seconds_per_attempt))
    capacity = min(limit, time_capacity) - controls_per_batch
    if capacity < attempts_per_root:
        raise ValueError('one root plus controls does not fit the estimated batch budget')
    roots_per_batch = capacity // attempts_per_root
    strata = {}
    for name, key in (
        ('training', 'minimum_training_roots'),
        ('calibration_normal', 'minimum_calibration_normal_roots'),
        ('test_normal', 'minimum_test_normal_roots'),
        ('test_positive', 'minimum_test_positive_roots'),
    ):
        roots = protocol[key]
        batches = math.ceil(roots / roots_per_batch)
        attempts = roots * attempts_per_root + batches * controls_per_batch
        strata[name] = {'required_independent_roots': roots, 'planned_batches': batches,
                        'planned_attempts_including_controls': attempts}
    batches = sum(row['planned_batches'] for row in strata.values())
    attempts = sum(row['planned_attempts_including_controls'] for row in strata.values())
    return {
        'status': 'planning_only', 'protocol_sha256': PROTOCOL_SHA256,
        'assumptions': {'attempts_per_root': attempts_per_root,
                        'controls_per_batch': controls_per_batch,
                        'seconds_per_attempt': seconds_per_attempt},
        'roots_per_batch': roots_per_batch, 'strata': strata,
        'total_independent_roots': sum(row['required_independent_roots'] for row in strata.values()),
        'planned_batches': batches, 'planned_attempts_including_controls': attempts,
        'estimated_serial_seconds': attempts * seconds_per_attempt,
        'per_batch_storage_limit_bytes': protocol['maximum_storage_bytes_per_explicit_batch'],
        'estimated_storage_bytes': None, 'estimated_provider_cost': None,
        'automatic_batch_extension': False, 'trials_started': 0,
        'independence_verified': False, 'product_activation_authorized': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempts-per-root', type=int, required=True)
    parser.add_argument('--controls-per-batch', type=int, required=True)
    parser.add_argument('--seconds-per-attempt', type=float, required=True)
    args = parser.parse_args()
    try:
        result = plan(**vars(args))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
