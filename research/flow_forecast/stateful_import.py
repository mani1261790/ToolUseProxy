"""Revalidate saved synthetic captures before admitting them to research collection.

This verifies local consistency, not a provider attestation or task independence.
"""
from dataclasses import asdict

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read, read_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from .generated_stateful import validate as validate_generated
from .stateful_collection import dataset_from_traces, generated_completion


def read_capture(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_stateful_capture_directory')
    total = 0

    def read(name):
        nonlocal total
        raw = _read(directory / name)
        total += len(raw)
        if total > 32 * 1024 * 1024:
            raise ForecastDataError('stateful_import_size_limit')
        return _json(raw)

    try:
        intent, execution, report = (read(name + '.json') for name in ('intent', 'execution', 'report'))
        if (set(report) != {'schema', 'status', 'intent_sha', 'execution_sha', 'dataset_sha',
                           'trial_charges', 'elapsed_seconds', 'artifact_bytes_before_report', 'conditions',
                           'independent_new_task_count', 'generator_model_verified', 'unused_holdout',
                           'new_model_calls', 'scope', 'native_codex_hook_delivery',
                           'prepared_generation_sha', 'source_generation_calls'}
                or report['schema'] != 1 or report['status'] != 'completed'
                or digest(intent) != report['intent_sha'] or digest(execution) != report['execution_sha']
                or digest(read('implementation.json')) != intent['implementation']
                or set(execution) != set(intent) | {'environment', 'context_sha'}
                or any(execution[key] != value for key, value in intent.items())):
            raise ForecastDataError('stateful_capture_identity_mismatch')
        generation = intent['generator_evidence']
        if generation is not None:
            validate_generated(generation)
            if generation['plan'] != intent['plan']:
                raise ForecastDataError('stateful_generated_plan_mismatch')
        if (report['prepared_generation_sha'] != (generation['prepared_sha'] if generation else None)
                or report['source_generation_calls'] != int(generation is not None)
                or report['new_model_calls'] != 0):
            raise ForecastDataError('stateful_generation_identity_mismatch')
        conditions = [read(mode + '.json') for mode in ('observe', 'enforce')]
        if report['conditions'] != conditions:
            raise ForecastDataError('stateful_condition_mismatch')
        charges = 0
        for mode, condition in zip(('observe', 'enforce'), conditions):
            controls = condition['controls']
            if (condition['mode'] != mode or len(controls) != 3
                    or any(c['observer_state'] != 'complete' for c in controls)
                    or controls[0]['task_success'] != 'yes' or controls[0]['protected_arrival'] != 'no'
                    or controls[1]['protected_arrival'] != 'yes'
                    or controls[2]['decision'] != 'deny' or controls[2]['process_started'] != 'no'
                    or controls[2]['receiver_arrival'] != 'no'):
                raise ForecastDataError('stateful_controls_failed')
            for source, policy in (('public', 'observe'), ('protected', 'observe'), ('protected', 'enforce')):
                charges += 1
                if read(f'reservation-{charges}.json') != {'trial': f'{mode}-control-{source}-{policy}'}:
                    raise ForecastDataError('stateful_control_reservation_mismatch')
            for number, row in enumerate(condition['steps'], 1):
                charges += 1
                if (read(f'{mode}-step-{number}.json') != row
                        or read(f'{mode}-guard-{number}.json') != {
                            'step_id': row['step_id'], 'command_sha': row['command_sha'],
                            'receipt': row['guard_receipt']}
                        or read(f'reservation-{charges}.json') != {
                            'trial': f'{mode}-step-{number}', 'step_id': row['step_id'],
                            'command_sha': row['command_sha']}):
                    raise ForecastDataError('stateful_step_artifact_mismatch')
            if condition['task_completion'] != generated_completion(generation, intent['plan'], condition):
                raise ForecastDataError('stateful_completion_mismatch')
        if type(report['trial_charges']) is not int or report['trial_charges'] != charges or charges > 20:
            raise ForecastDataError('stateful_charge_mismatch')
        rebuilt = dataset_from_traces(execution, conditions)
        data = read_dataset(directory / 'dataset')
        if (data != rebuilt or read('dataset/manifest.json')['dataset_digest'] != report['dataset_sha']):
            raise ForecastDataError('stateful_dataset_mismatch')
        return data, {'execution': execution, 'report': report, 'dataset_sha': digest(asdict(data))}
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_stateful_capture') from error
