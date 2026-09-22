"""Explicit commands for synthetic issue preview, queueing, mapping and delivery."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from tooluseproxy.pilot_worker import SyncFailure
from .agent import Proposal as ActionProposal
from .models import RecordError, canonical
from .outbox import Outbox
from .preflight import LabError
from .proposal import IssueProposal, digest, document, proposals
from .replay import decode_result
from .search_state import APPLICATION_ID


def read_proposals(directory: Path):
    path = (directory / 'search.sqlite3').resolve()
    if path.name != 'search.sqlite3':
        raise LabError('invalid_replay_storage')
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        if conn.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID:
            raise LabError('replay_schema_mismatch')
        row = conn.execute('SELECT substr(value,1,1048577) FROM state WHERE id=1').fetchone()
        if not row or not isinstance(row[0], str) or len(row[0]) > 1048576:
            raise LabError('invalid_replay_record')
        state = json.loads(row[0])
        if state['identity']['kind'] != 'synthetic-replay-v1':
            raise LabError('replay_schema_mismatch')
        cases = state['cases']
        if not isinstance(cases, list) or len(cases) > 6:
            raise LabError('invalid_replay_record')
        results, pending = [], []
        for case in cases:
            actions = ActionProposal.parse({'status': 'propose', 'actions': case['actions']}).actions
            if case['status'] == 'completed':
                result = decode_result(case['result'])
                if (result.spec.run_id != case['run_id'] or result.actions != actions
                        or result.spec.detector_revision != case['detector_revision']):
                    raise LabError('invalid_replay_record')
                results.append(result)
            elif case['status'] == 'pending':
                for index, action in enumerate(actions):
                    pending.append(IssueProposal(
                        'incomplete_observation', asdict(action), case['detector_revision'],
                        case['run_id'], digest({'pending': case['run_id'], 'index': index})[:32],
                        None, ('incomplete_observation',), True, False, pending=True,
                    ))
            else:
                raise LabError('invalid_replay_record')
        return (*proposals(tuple(results)), *pending)
    except (KeyError, TypeError, ValueError, IndexError):
        raise LabError('invalid_replay_record') from None
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    preview = commands.add_parser('preview')
    preview.add_argument('--campaign', type=Path, required=True)
    enqueue = commands.add_parser('enqueue')
    enqueue.add_argument('--campaign', type=Path, required=True)
    for name in ('enqueue', 'status', 'sync', 'bind'):
        command = enqueue if name == 'enqueue' else commands.add_parser(name)
        command.add_argument('--outbox', type=Path, required=True)
        command.add_argument('--repository', required=True)
        if name == 'bind':
            command.add_argument('--problem-key', required=True)
            command.add_argument('--issue', type=int, required=True)
        if name == 'sync':
            command.add_argument('--limit', type=int, default=20)
    args = parser.parse_args(argv)
    try:
        if args.command == 'preview':
            result = [{'problem_key': p.problem_key, 'delivery_key': p.delivery_key,
                       'title': document(p)[0], 'body': document(p)[1]}
                      for p in read_proposals(args.campaign)]
        else:
            # Validate the source before creating the destination database.
            items = read_proposals(args.campaign) if args.command == 'enqueue' else ()
            with Outbox(args.outbox, args.repository) as outbox:
                if args.command == 'enqueue':
                    result = {'enqueued': sum(outbox.enqueue(item) for item in items),
                              'states': outbox.summary()}
                elif args.command == 'sync':
                    result = outbox.sync(limit=args.limit)
                elif args.command == 'bind':
                    outbox.bind(args.problem_key, args.issue)
                    result = {'status': 'bound'}
                else:
                    rows = outbox.db.execute(
                        'SELECT delivery,problem,state,issue,error FROM proposals ORDER BY rowid DESC LIMIT 100'
                    ).fetchall()
                    result = {'states': outbox.summary(), 'latest_items': [dict(row) for row in rows]}
    except (LabError, SyncFailure, RecordError, OSError, sqlite3.Error, ValueError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, (LabError, SyncFailure, RecordError)) else 'issue_io_error'
        print(canonical({'status': 'not_completed', 'reason': reason}))
        return 1
    print(canonical(result))
    return 1 if args.command == 'sync' and result['status'] != 'ok' else 0


if __name__ == '__main__':
    raise SystemExit(main())
