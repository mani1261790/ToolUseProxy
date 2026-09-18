"""Explicit, one-shot artificial experiment commands; never starts a Hook or daemon."""
from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time

from hook_monitor.evaluation.flow_forecast.dataset import read_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from tooluseproxy.authority_state import AuthorityError
from tooluseproxy.integrations.authority import registered_workspace_authority_lease
from .explain import history_text
from .journal import Journal
from .source import EventSource
from .synthetic import SyntheticSource
from .worker import run_one


def inspect_input(database, workspace, session):
    """Inspect version metadata under the same administrative lease as workers."""
    source = EventSource(database)
    with closing(source.connect()) as connection:
        with registered_workspace_authority_lease(database, connection, workspace) as state:
            if state is not None and state.phase != 'active':
                return {'status': 'administratively_inactive'}
            snapshot = source.snapshot(workspace, session)
            return {'status': 'out_of_domain', 'input_digest': snapshot.input_digest,
                    'protection_digest': snapshot.protection_digest, 'policy_digest': snapshot.policy_digest,
                    'observed_sequence': snapshot.observed_sequence,
                    'prediction': None, 'reason': 'recorded_structure_model_not_validated'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('init', help='Create a separate forecast journal exclusively')
    create.add_argument('--journal', type=Path, required=True)
    inspect = commands.add_parser('inspect-input', help='Read version metadata; no real-input prediction')
    inspect.add_argument('--events-db', type=Path, required=True)
    inspect.add_argument('--workspace', required=True)
    inspect.add_argument('--session', required=True)
    for name in ('enable', 'disable', 'candidates', 'enqueue', 'run', 'recover', 'history'):
        command = commands.add_parser(name)
        command.add_argument('--journal', type=Path, required=True)
        command.add_argument('--synthetic-dataset', type=Path, required=True)
        if name == 'history':
            command.add_argument('--format', choices=('json', 'text'), default='json')
        if name in {'enqueue', 'run'}:
            command.add_argument('--model', type=Path, required=True)
        if name == 'enqueue':
            command.add_argument('--candidate', required=True)
            command.add_argument('--policy-mode', choices=('observe', 'enforce'), default='observe')
            command.add_argument('--horizon', type=int, choices=(1, 2, 4, 8), default=4)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            Journal.create(args.journal)
            result = {'status': 'initialized', 'enabled': False}
        elif args.command == 'inspect-input':
            result = inspect_input(args.events_db, args.workspace, args.session)
        else:
            journal = Journal(args.journal)
            source = SyntheticSource(args.synthetic_dataset, getattr(args, 'model', None), journal)
            if args.command in {'enable', 'disable'}:
                # This controls only the isolated experiment journal. It cannot
                # enroll/reactivate or disable a ToolUseProxy protected project.
                if args.command == 'enable':
                    read_dataset(args.synthetic_dataset)
                generation = journal.configure(source.workspace, enabled=args.command == 'enable')
                result = {'status': args.command + 'd', 'generation': generation}
            elif journal.configured(source.workspace) is None:
                result = {'status': 'unconfigured'}
            elif args.command == 'candidates':
                result = {'status': 'available', 'candidates': [
                    {'candidate': p.prefix_id, 'observed_sequence': p.max_sequence_no, 'task_kind': p.task_kind}
                    for p in read_dataset(args.synthetic_dataset).prefixes]}
            elif args.command == 'enqueue':
                request = source.request(args.candidate, now=time.time(), policy_mode=args.policy_mode, horizon=args.horizon)
                current = source.current(request)
                status = request.validity(current.binding, current.model_digest, time.time())
                if status == 'current':
                    status = journal.enqueue(request, current=current.binding, now=time.time())
                result = {'status': status, 'request_id': request.request_id}
            elif args.command == 'run':
                result = run_one(journal, source.workspace, args.model, read_current=source.current)
            elif args.command == 'recover':
                result = {'status': 'recovered', 'interrupted': journal.recover(source.workspace, now=time.time())}
            else:
                result = {'status': 'history', 'historical_only': True, 'records': journal.history(source.workspace)}
            result['synthetic_only'] = True
        result['policy_decisions_changed'] = False
        if getattr(args, 'format', 'json') == 'text' and result['status'] == 'history':
            print(history_text(result['records']))
        else:
            print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (ForecastDataError, AuthorityError, OSError, sqlite3.Error, ValueError):
        # Neither paths, payloads nor underlying exception text are emitted.
        print(json.dumps({'status': 'unavailable', 'policy_decisions_changed': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
