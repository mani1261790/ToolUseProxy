"""Bind finite interventions to the exact closed computation captured in a task.

Hash consistency is not independent attestation. These observations remain
finite and never automatically promote semantic truth or independent samples.
"""
import hashlib
import math
import re

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .task_world_import import read_capture
from .task_world_interventions import cases, script
from .task_worlds import definition, encoded, operation_script


def read_interventions(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_intervention_directory')
    total = 0
    def read(name):
        nonlocal total
        raw = _read(directory / (name + '.json'))
        total += len(raw)
        if total > 1024 * 1024:
            raise ForecastDataError('intervention_evidence_size_limit')
        return _json(raw)
    try:
        intent, execution, report = (read(name) for name in ('intent', 'execution', 'report'))
        selected = cases(intent['world'])
        if (intent['definition'] != definition(intent['world']) or intent['cases'] != selected
                or intent['planned_trials'] != len(selected)
                or digest(read('implementation')) != intent['implementation_sha']
                or execution['intent_sha'] != digest(intent) or report['intent_sha'] != digest(intent)
                or report['execution_sha'] != digest(execution) or report['status'] != 'completed'
                or report['semantic_truth_promoted'] is not False or report['native_hook_tested'] is not False
                or report['scope'] != 'finite_input_interventions_not_universal_information_flow_proof'
                or any(type(report[k]) is not int or report[k] != 0 for k in ('new_model_calls', 'independent_new_tasks_accepted'))
                or type(report['trial_charges']) is not int or report['trial_charges'] != len(selected)
                or not re.fullmatch('sha256:[a-f0-9]{64}', execution['image'])
                or not re.fullmatch('[a-f0-9]{64}', execution['context_sha'])):
            raise ValueError
        if any(type(value['schema']) is not int or value['schema'] != 1 for value in (intent, report)):
            raise ValueError
        limits = intent['limits']
        if (set(limits) != {'trials', 'seconds', 'bytes'} or any(type(v) is not int for v in limits.values())
                or limits['trials'] != 20 or limits['bytes'] != 1024 * 1024 * 1024
                or not 1 <= limits['seconds'] <= 1800 or type(report['elapsed_seconds']) not in (int, float)
                or not math.isfinite(report['elapsed_seconds']) or not 0 <= report['elapsed_seconds'] < limits['seconds']
                or type(report['artifact_bytes_before_report']) is not int
                or not 0 <= report['artifact_bytes_before_report'] < limits['bytes']):
            raise ValueError
        rows, containers = [], []
        for number, case in enumerate(selected, 1):
            if read(f'reservation-{number}') != {'number': number, 'case_sha': digest(case),
                    'script_sha': hashlib.sha256(script(intent['world'], case).encode()).hexdigest()}:
                raise ValueError
            row = {'case': case['name'], 'input_sha': digest(case['input']),
                   'output_sha': hashlib.sha256(encoded(case['answer'])).hexdigest(),
                   'answer_matched': True, 'changed_from_baseline': case['answer'] != selected[0]['answer']}
            if read(f'result-{number}') != row:
                raise ValueError
            rows.append(row)
            path = directory / f'container-{number}.json'
            if path.exists() or path.is_symlink():
                container = read(f'container-{number}')
                if (set(container) != {'name', 'image'} or container['image'] != execution['image']
                        or not re.fullmatch('tup-lab-[a-f0-9]{32}', container['name'])):
                    raise ValueError
                containers.append(container['name'])
        if (report['results'] != rows or len(containers) not in (0, len(selected))
                or len(set(containers)) != len(containers)):
            raise ValueError
        return {'intent': intent, 'execution': execution, 'report': report,
                'container_identities_recorded': bool(containers)}
    except (KeyError, TypeError, ValueError, LabError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_intervention_evidence') from error


def bind_capture(capture_directory, intervention_directory):
    _, capture = read_capture(capture_directory)
    evidence = read_interventions(intervention_directory)
    left, right = capture['intent'], evidence['intent']
    if (left['world'] != right['world'] or left['definition'] != right['definition']
            or capture['execution']['context_sha'] != evidence['execution']['context_sha']):
        raise ForecastDataError('intervention_capture_identity_mismatch')
    observed = capture['report']['conditions'][0]['steps']
    if len(observed) < 2 or not observed[1]['dispatched']:
        raise ForecastDataError('intervention_computation_not_observed')
    # The compute command does not contain the receiver address. Reconstruct its
    # exact bytes, not merely the program label, before linking the baseline.
    command = operation_script(left['world'], 2, left['variant'], '172.18.0.2', observed[1]['step_id'])
    baseline = evidence['report']['results'][0]
    if (observed[1]['command_sha'] != hashlib.sha256(command.encode()).hexdigest()
            or baseline['output_sha'] != observed[1]['observation']['body_sha']
            or baseline['input_sha'] != digest(left['definition']['input'])):
        raise ForecastDataError('intervention_computation_mismatch')
    return {'schema': 1, 'world': left['world'], 'capture_root': left['root'],
            'capture_report_sha': digest(capture['report']), 'intervention_report_sha': digest(evidence['report']),
            'definition_sha': digest(left['definition']), 'matched_compute_command_sha': observed[1]['command_sha'],
            'changed_cases': [r['case'] for r in evidence['report']['results'] if r['changed_from_baseline']],
            'semantic_truth_promoted': False, 'independent_new_tasks_accepted': 0,
            'scope': 'same_closed_computation_finite_input_dependence_only'}
