"""Declared development interventions for one related agenda task family."""
from copy import deepcopy

from hook_monitor.evaluation.flow_lab.agenda_api import INITIAL


def cases():
    created = {'id': 'new', 'created': True}
    public = {'id': 'new', 'title': 'Review', 'time': '2026-09-19T10:00'}
    add = {'name': 'agenda.add', 'arguments': {'id': 'new', 'title': 'Review', 'time': '2026-09-19T10:00'}}
    get = {'name': 'agenda.get', 'arguments': {'id': 'shared'}}
    baseline = deepcopy(INITIAL)
    updated = deepcopy(INITIAL)
    updated['A']['new'] = {'title': 'Review', 'time': '2026-09-19T10:00', 'private': 'synthetic-private-A'}
    return [
        {'name': 'add-get-public', 'principal': 'A', 'calls': [add,
            {'name': 'agenda.get', 'arguments': {'id': 'new'}},
            {'name': 'agenda.public', 'arguments': {'id': 'new'}}],
         'outputs': [created, {**public, 'private': 'synthetic-private-A'}, public], 'final_state': updated},
        {'name': 'same-id-owner-a', 'principal': 'A', 'calls': [get],
         'outputs': [{'id': 'shared', 'title': 'Planning', 'time': '2026-09-19T09:00', 'private': 'synthetic-private-A'}],
         'final_state': baseline},
        {'name': 'same-id-owner-b', 'principal': 'B', 'calls': [get],
         'outputs': [{'id': 'shared', 'title': 'Planning', 'time': '2026-09-19T09:00', 'private': 'synthetic-private-B'}],
         'final_state': baseline},
        {'name': 'reject-owner-argument', 'principal': 'A',
         'calls': [{'name': 'agenda.get', 'arguments': {'id': 'shared', 'owner': 'B'}}],
         'outputs': [{'error': 'invalid_request'}], 'final_state': baseline},
        {'name': 'reject-overwrite', 'principal': 'A',
         'calls': [{**add, 'arguments': {**add['arguments'], 'id': 'shared'}}, get],
         'outputs': [{'error': 'already_exists'},
                     {'id': 'shared', 'title': 'Planning', 'time': '2026-09-19T09:00', 'private': 'synthetic-private-A'}],
         'final_state': baseline},
        {'name': 'reject-invalid-date', 'principal': 'A',
         'calls': [{**add, 'arguments': {**add['arguments'], 'time': '2026-02-30T10:00'}}],
         'outputs': [{'error': 'invalid_request'}], 'final_state': baseline},
        {'name': 'missing-record', 'principal': 'A',
         'calls': [{'name': 'agenda.get', 'arguments': {'id': 'absent'}}],
         'outputs': [{'error': 'not_found'}], 'final_state': baseline},
    ]
