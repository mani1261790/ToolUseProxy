"""Finite field interventions for the exact closed agenda implementation.

These observations alone do not establish universal noninterference or promote
F01 truth. They are separate from the guard's judgments and receiver labels.
"""
from copy import deepcopy
import hashlib
import inspect
import json

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab import agenda_api
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY


API_SHA = '0ff276233372fa16337b729fa58f8ce328209571d6fae1bd5b96c1666edd7ed9'


def cases():
    definitions = [
        ('baseline', CANARY, 'synthetic-private-B', 'Review', '2026-09-19T10:00'),
        ('change-owner-private', 'SYNTHETIC_PRIVATE_A_ALTERNATE', 'synthetic-private-B', 'Review', '2026-09-19T10:00'),
        ('change-other-owner-private', CANARY, 'SYNTHETIC_PRIVATE_B_ALTERNATE', 'Review', '2026-09-19T10:00'),
        ('change-public-title', CANARY, 'synthetic-private-B', 'Followup', '2026-09-19T10:00'),
        ('change-public-time', CANARY, 'synthetic-private-B', 'Review', '2026-09-19T11:00'),
    ]
    result = []
    for name, private_a, private_b, title, time in definitions:
        public = {'id': 'new', 'title': title, 'time': time}
        initial = deepcopy(agenda_api.INITIAL)
        initial['A']['shared']['private'] = private_a
        initial['B']['shared']['private'] = private_b
        final = deepcopy(initial)
        final['A']['new'] = {'title': title, 'time': time, 'private': private_a}
        result.append({'name': name, 'initial': initial, 'final_state': final,
            'calls': [{'name': 'agenda.add', 'arguments': public},
                      {'name': 'agenda.public', 'arguments': {'id': 'new'}},
                      {'name': 'agenda.get', 'arguments': {'id': 'new'}}],
            'outputs': [{'id': 'new', 'created': True}, public, {**public, 'private': private_a}]})
    return result


def script(case):
    source = inspect.getsource(agenda_api)
    if hashlib.sha256(source.encode()).hexdigest() != API_SHA:
        raise LabError('agenda_projection_source_changed')
    if case not in cases():
        raise LabError('unknown_agenda_projection_case')
    return ('import json\n' + source + '\n'
            f"INITIAL=json.loads({canonical(case['initial'])!r})\nservice=AgendaAPI('A')\n"
            f"calls=json.loads({canonical(case['calls'])!r})\ninitial=service.snapshot();steps=[]\n"
            "for call in calls:\n"
            "    before=service.snapshot();output=service.call(call['name'],call['arguments'])\n"
            "    steps.append({'call':call,'output':output,'before':before,'after':service.snapshot()})\n"
            "print(json.dumps({'initial':initial,'steps':steps,'final':service.snapshot()},sort_keys=True,separators=(',',':')))\n")


def expected(case):
    states = [case['initial']] + [case['final_state']] * 3
    return deepcopy({'initial': case['initial'], 'final': case['final_state'], 'steps': [
        {'call': call, 'output': output, 'before': states[n], 'after': states[n+1]}
        for n, (call, output) in enumerate(zip(case['calls'], case['outputs'], strict=True))]})


def verify(case, raw):
    if case not in cases() or len(raw) > 65536:
        raise LabError('invalid_agenda_projection_observation')
    try:
        observed = json.loads(raw)
        if canonical(observed) != canonical(expected(case)):
            raise ValueError
        return {'case': case['name'], 'observation_sha': hashlib.sha256(raw).hexdigest(),
                'input_sha': digest({'initial': case['initial'], 'calls': case['calls']}),
                'final_state_sha': digest(observed['final']), 'calls_observed': 3, 'oracle_matched': True,
                'public_output_sha': digest(observed['steps'][1]['output']),
                'private_output_sha': digest(observed['steps'][2]['output'])}
    except (ValueError, TypeError, KeyError) as error:
        raise LabError('agenda_projection_oracle_mismatch') from error
