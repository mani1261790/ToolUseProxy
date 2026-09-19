"""Summarize verified pilot costs without launching or authorizing more batches."""
import argparse
import json
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_forecast.protocol import PROTOCOL_SHA256, load_protocol
from .intervention_evidence import bind_capture, read_interventions
from .task_world_import import read_capture


def budget(pairs):
    if type(pairs) is not list or not 1 <= len(pairs) <= 100:
        raise ForecastDataError('invalid_budget_inputs')
    captures, interventions, bindings = {}, {}, []
    for pair in pairs:
        if (type(pair) is not dict or set(pair) != {'capture', 'interventions'}
                or any(type(v) is not str or not v for v in pair.values())):
            raise ForecastDataError('invalid_budget_inputs')
        capture_path, intervention_path = Path(pair['capture']), Path(pair['interventions'])
        _, capture = read_capture(capture_path)
        intervention = read_interventions(intervention_path)
        binding = bind_capture(capture_path, intervention_path)
        # Reject changed evidence between the reader and binding passes.
        if (binding['capture_report_sha'] != digest(capture['report'])
                or binding['intervention_report_sha'] != digest(intervention['report'])):
            raise ForecastDataError('budget_evidence_changed')
        root = capture['intent']['root']
        if root in captures:
            raise ForecastDataError('duplicate_budget_capture')
        captures[root] = capture
        # A shared intervention batch is paid once, never once per replay.
        interventions[binding['intervention_report_sha']] = intervention
        bindings.append(binding)
    records = list(captures.values()) + list(interventions.values())
    protocol = load_protocol()
    strata = {name: protocol[key] for name, key in (
        ('training', 'minimum_training_roots'),
        ('calibration_normal', 'minimum_calibration_normal_roots'),
        ('test_normal', 'minimum_test_normal_roots'),
        ('test_positive', 'minimum_test_positive_roots'))}
    roots = sum(strata.values())
    return {
        'schema': 1, 'status': 'pilot_costs_and_conditional_plan_only',
        'protocol_sha256': PROTOCOL_SHA256, 'bindings': bindings,
        'observed_selected_completed_batches': {
            'captures': len(captures), 'interventions': len(interventions),
            'trial_charges': sum(r['report']['trial_charges'] for r in records),
            'elapsed_seconds': sum(r['report']['elapsed_seconds'] for r in records),
            'artifact_bytes_before_reports': sum(r['report']['artifact_bytes_before_report'] for r in records),
            'blocked_enforce_captures': sum(r['report']['conditions'][1]['termination'] == 'blocked'
                                           for r in captures.values()),
            'includes_model_preparation': False, 'includes_failed_or_unlisted_batches': False,
            'complete_storage_measurement': False,
        },
        'conditional_collection_plan': {
            'required_independent_roots_by_stratum': strata, 'required_independent_roots': roots,
            'capture_batches_per_root': 1, 'intervention_batches_per_root': 1,
            'capture_trial_reservations_per_root': 14, 'intervention_trial_reservations_per_root': 3,
            'explicit_batches': roots * 2, 'trial_reservations': roots * 17,
            'seconds_limit_per_batch': 180, 'storage_limit_bytes_per_batch': 1024 ** 3,
            'serial_batch_deadline_sum_seconds': roots * 2 * 180,
            'model_calls_assuming_one_successful_plan_per_root': roots,
            'estimated_end_to_end_seconds': None, 'estimated_total_storage_bytes': None,
            'estimated_provider_cost': None,
            'assumptions': ['one_new_accepted_design_per_root', 'one_capture_and_one_intervention_batch_per_design',
                            'all_plans_succeed_without_retry', 'all_required_outcome_strata_filled',
                            'no_additional_tool_or_model_generalization_runs'],
        },
        'independence_verified': False, 'prior_nonuse_verified': False,
        'automatic_batch_extension': False, 'trials_started': 0,
        'scope': 'completed_pilot_subset_not_total_project_cost_or_execution_authorization',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    args = parser.parse_args(argv)
    raw = _read(args.inputs)
    if len(raw) > 128 * 1024:
        raise ForecastDataError('budget_inputs_size_limit')
    print(json.dumps(budget(_json(raw)), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
