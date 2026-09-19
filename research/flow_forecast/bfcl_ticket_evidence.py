"""Bind finite field interventions to observed Ticket I/O, without truth promotion."""
import hashlib
import math
from pathlib import Path
import re

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from .bfcl_ticket_interventions import COMMIT, SOURCE_SHA, cases, script, verify
from .bfcl_ticket_import import read_capture


def read_interventions(directory, source):
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_ticket_intervention_directory')
    total = 0
    def raw(name):
        nonlocal total
        data = _read(directory / (name + '.json'))
        total += len(data)
        if total > 32 * 1024**2:
            raise ForecastDataError('ticket_intervention_size_limit')
        return data
    def read(name):
        return _json(raw(name))
    try:
        intent, execution, report, implementation = (read(n) for n in ('intent','execution','report','implementation'))
        if (intent['schema'] != 1 or type(intent['schema']) is not int
                or intent['suite'] != 'ticket_field_interventions_v1'
                or intent['source_commit'] != COMMIT or intent['source_sha'] != SOURCE_SHA
                or intent['cases'] != cases() or type(intent['planned_trials']) is not int or intent['planned_trials'] != 20
                or type(report['schema']) is not int or report['schema'] != 1 or report['status'] != 'completed'
                or report['scope'] != 'finite_ticket_interventions_not_universal_truth_or_unseen_evaluation'
                or report['all_oracles_matched'] is not True or report['receiver_observed'] is not False
                or any(type(report[k]) is not int or report[k] != n for k,n in
                       [('trial_charges',20),('api_calls',15),('new_model_calls',0),('accepted_independent_groups',0)])
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
                or type(report['artifact_bytes_before_report']) is not int
                or not 0 <= report['artifact_bytes_before_report'] < limits['bytes']):
            raise ValueError
        files = implementation['files']
        name = 'research/flow_forecast/bfcl_ticket_interventions.py'
        if (implementation['sha256'] != digest(files) or len({f['path'] for f in files}) != len(files)
                or [f['sha256'] for f in files if f['path'] == name] !=
                    [hashlib.sha256((Path(__file__).resolve().parents[2] / name).read_bytes()).hexdigest()]):
            raise ValueError
        containers, results, observations = set(), [], []
        for index, case in enumerate(cases(), 1):
            reservation = read(f'reservation-{index}')
            container = reservation['container']
            if not re.fullmatch('tup-lab-[a-f0-9]{32}', container) or container in containers:
                raise ValueError
            containers.add(container)
            if reservation != dict(case_sha=digest(case), script_sha=hashlib.sha256(script(source,case).encode()).hexdigest(),
                    trial_charges=4, operations=['synthetic_state_setup','resolve_ticket','get_user_tickets','get_ticket'],
                    container=container, image=execution['image']):
                raise ValueError
            observation = raw(f'observation-{index}')
            result = verify(case, observation)
            if result != read(f'result-{index}') or result['oracle_matched'] is not True:
                raise ValueError
            results.append(result)
            observations.append(_json(observation))
        if report['results'] != results or (directory / 'failure.json').exists():
            raise ValueError
        for stem in ('reservation','observation','result'):
            if {p.name for p in directory.glob(stem+'-*.json')} != {f'{stem}-{i}.json' for i in range(1,6)}:
                raise ValueError
        return {'intent':intent,'execution':execution,'report':report,'observations':observations}
    except (KeyError,TypeError,ValueError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_ticket_intervention_evidence') from error


def bind_capture(capture, interventions, source):
    _, original = read_capture(capture, source)
    checked = read_interventions(interventions, source)
    if original['execution']['context_sha'] != checked['execution']['context_sha']:
        raise ForecastDataError('ticket_intervention_context_mismatch')
    baseline = checked['observations'][0]
    variant = original['intent']['variant']
    count = 0
    for condition in original['report']['conditions']:
        for row in condition['steps']:
            if row['number'] == 2 and row['dispatched']:
                observed = row['observation']['dispatch']
                if (observed['before'] != baseline['state'] or observed['after'] != baseline['state']
                        or observed['output'] != baseline['outputs'][1 if variant == 'public' else 2]):
                    raise ForecastDataError('ticket_intervention_baseline_mismatch')
                count += 1
    if not count:
        raise ForecastDataError('ticket_intervention_query_not_observed')
    return {'schema':1,'capture_root':original['intent']['root'], 'capture_report_sha':digest(original['report']),
            'intervention_report_sha':digest(checked['report']), 'source_sha':SOURCE_SHA,
            'query_observations_bound':count, 'semantic_truth_promoted':False,
            'capture_image':original['execution']['image'], 'intervention_image':checked['execution']['image'],
            'identical_image_verified':original['execution']['image'] == checked['execution']['image'],
            'scope':'finite_ticket_field_interventions_not_universal_noninterference'}
