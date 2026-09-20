"""Validate finite agenda interventions and bind them to an actual API capture."""
import hashlib
import math
import re

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .agenda_import import read_capture
from .agenda_projection import API_SHA, cases, script, verify


def read_interventions(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_agenda_projection_directory')
    total = 0
    def raw(name):
        nonlocal total
        data = _read(directory / (name + '.json'))
        total += len(data)
        if total > 32 * 1024**2:
            raise ForecastDataError('agenda_projection_size_limit')
        return data
    def read(name):
        return _json(raw(name))
    try:
        intent, execution, report, implementation = (read(n) for n in ('intent','execution','report','implementation'))
        if (type(intent['schema']) is not int or intent['schema'] != 1 or intent['suite'] != 'projection'
                or intent['cases'] != cases() or type(intent['planned_trials']) is not int or intent['planned_trials'] != 15
                or type(report['schema']) is not int or report['schema'] != 1 or report['status'] != 'completed'
                or report['suite'] != 'projection' or report['semantic_truth_promoted'] is not False
                or report['receiver_observed'] is not False or report['native_hook_tested'] is not False
                or report['scope'] != 'closed_stateful_api_development_not_F01_or_unseen_evaluation'
                or type(report['trial_charges']) is not int or report['trial_charges'] != 15
                or type(report['new_model_calls']) is not int or report['new_model_calls'] != 0
                or type(report['independent_new_tasks_accepted']) is not int or report['independent_new_tasks_accepted'] != 0
                or report['intent_sha'] != digest(intent) or execution['intent_sha'] != digest(intent)
                or report['execution_sha'] != digest(execution) or digest(implementation) != intent['implementation_sha']
                or not re.fullmatch('sha256:[a-f0-9]{64}', execution['image'])
                or not re.fullmatch('[a-f0-9]{64}', execution['context_sha'])):
            raise ValueError
        limits = intent['limits']
        if (set(limits) != {'trials','seconds','bytes'} or any(type(v) is not int for v in limits.values())
                or limits['trials'] != 20 or limits['bytes'] != 1024**3 or not 1 <= limits['seconds'] <= 1800
                or type(report['elapsed_seconds']) not in (int,float) or not math.isfinite(report['elapsed_seconds'])
                or not 0 <= report['elapsed_seconds'] < limits['seconds']
                or type(report['artifact_bytes_before_report']) is not int or not 0 <= report['artifact_bytes_before_report'] < limits['bytes']):
            raise ValueError
        files = implementation['files']
        if (digest(files) != implementation['sha256'] or len({f['path'] for f in files}) != len(files)
                or [f['sha256'] for f in files if f['path'] == 'hook_monitor/evaluation/flow_lab/agenda_api.py'] != [API_SHA]):
            raise ValueError
        charged, rows, containers = 0, [], set()
        for index, case in enumerate(cases(), 1):
            source_sha = hashlib.sha256(script(case).encode()).hexdigest()
            for number, call in enumerate(case['calls'], 1):
                charged += 1
                if read(f'reservation-{charged}') != {'number':charged,'case_sha':digest(case),'call_number':number,
                                                      'call_sha':digest(call),'script_sha':source_sha}:
                    raise ValueError
            container = read(f'container-{index}')
            if (set(container) != {'name','image'} or container['image'] != execution['image']
                    or not re.fullmatch('tup-lab-[a-f0-9]{32}', container['name']) or container['name'] in containers):
                raise ValueError
            containers.add(container['name'])
            observation = raw(f'observation-{index}')
            _json(observation)  # Reject ambiguous duplicate keys before oracle comparison.
            result = verify(case, observation)
            if read(f'result-{index}') != result:
                raise ValueError
            rows.append(result)
        if report['results'] != rows or (directory / 'failure.json').exists():
            raise ValueError
        for stem, size in (('reservation',15),('container',5),('observation',5),('result',5)):
            if {p.name for p in directory.glob(stem+'-*.json')} != {f'{stem}-{i}.json' for i in range(1,size+1)}:
                raise ValueError
        return {'intent':intent,'execution':execution,'report':report}
    except (KeyError,TypeError,ValueError,LabError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_agenda_projection_evidence') from error


def bind_capture(capture, interventions):
    _, original = read_capture(capture)
    checked = read_interventions(interventions)
    if original['execution']['context_sha'] != checked['execution']['context_sha']:
        raise ForecastDataError('agenda_projection_context_mismatch')
    baseline = checked['report']['results'][0]
    variant = original['intent']['variant']
    expected_sha = baseline['public_output_sha' if variant == 'public' else 'private_output_sha']
    observed = 0
    for condition in original['report']['conditions']:
        for row in condition['steps']:
            if row['number'] == 2 and row['dispatched']:
                if digest(row['observation']['dispatch']['output']) != expected_sha:
                    raise ForecastDataError('agenda_projection_baseline_mismatch')
                observed += 1
    if not observed:
        raise ForecastDataError('agenda_projection_query_not_observed')
    return {'schema':1, 'capture_root':original['intent']['root'], 'capture_report_sha':digest(original['report']),
            'intervention_report_sha':digest(checked['report']), 'api_source_sha':API_SHA,
            'query_observations_bound':observed, 'semantic_truth_promoted':False,
            'capture_image':original['execution']['image'], 'intervention_image':checked['execution']['image'],
            'identical_image_verified':original['execution']['image'] == checked['execution']['image'],
            'scope':'finite_closed_api_field_interventions_not_universal_noninterference'}
