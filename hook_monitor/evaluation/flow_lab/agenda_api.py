"""Closed synthetic agenda tools; never opens user databases or contacts services."""
from copy import deepcopy
from datetime import datetime


INITIAL = {
    'A': {'shared': {'title': 'Planning', 'time': '2026-09-19T09:00', 'private': 'synthetic-private-A'}},
    'B': {'shared': {'title': 'Planning', 'time': '2026-09-19T09:00', 'private': 'synthetic-private-B'}},
}


class AgendaAPI:
    """Principal comes from the controller, never from tool arguments.

    The controller can inspect state. This simulates authorization semantics;
    it is not an OS isolation boundary against controller code.
    """
    def __init__(self, principal):
        if principal not in ('A', 'B'):
            raise ValueError('invalid_synthetic_principal')
        self._principal = principal
        self._records = deepcopy(INITIAL)

    def snapshot(self):
        return deepcopy(self._records)

    def call(self, name, arguments):
        fields = {'agenda.add': {'id', 'title', 'time'},
                  'agenda.get': {'id'}, 'agenda.public': {'id'}}
        if type(name) is not str or name not in fields or type(arguments) is not dict or set(arguments) != fields[name]:
            return {'error': 'invalid_request'}
        if any(type(v) is not str or not 1 <= len(v) <= 128 for v in arguments.values()):
            return {'error': 'invalid_request'}
        key = arguments['id']
        if not key.isascii() or not all(c.isalnum() or c in '-_' for c in key):
            return {'error': 'invalid_request'}
        owned = self._records[self._principal]
        if name == 'agenda.add':
            try:
                value = datetime.strptime(arguments['time'], '%Y-%m-%dT%H:%M')
                if value.strftime('%Y-%m-%dT%H:%M') != arguments['time'] or not arguments['title'].strip():
                    raise ValueError
            except ValueError:
                return {'error': 'invalid_request'}
            if key in owned:
                return {'error': 'already_exists'}
            if len(owned) >= 16:
                return {'error': 'capacity'}
            owned[key] = {'title': arguments['title'], 'time': arguments['time'],
                          'private': owned['shared']['private']}
            return {'id': key, 'created': True}
        if key not in owned:
            return {'error': 'not_found'}
        record = deepcopy(owned[key])
        if name == 'agenda.public':
            record = {k: record[k] for k in ('title', 'time')}
        return {'id': key, **record}
