"""Explicit configuration/history for the optional forecast transport.

The worker is an optional source-checkout command; packaged Hooks do not import
research code. No command here changes protection, activation, or Hook settings.
"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sys

from hook_monitor.runtime.forecast.journal import Journal
from hook_monitor.runtime.forecast.source import connect
from tooluseproxy.integrations.authority import registered_workspace_authority_lease


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events-db', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init')
    configure = commands.add_parser('configure')
    configure.add_argument('--workspace', required=True)
    configure.add_argument('--mode', choices=('off', 'record', 'stop'), required=True)
    configure.add_argument('--model-digest', required=True)
    configure.add_argument('--threshold', type=float, default=.5)
    history = commands.add_parser('history')
    history.add_argument('--workspace', required=True)
    worker = commands.add_parser('worker')
    worker.add_argument('--model', type=Path, required=True)
    worker.add_argument('--seconds', type=float, default=60)
    args = parser.parse_args(argv)
    try:
        if args.events_db.name != 'events.db':
            raise ValueError('invalid_event_database_name')
        journal = Journal(args.events_db.parent / 'forecast.db')
        if args.command == 'init':
            with closing(connect(args.events_db)) as conn:
                conn.execute('SELECT workspace_id FROM workspaces LIMIT 1').fetchone()
            Journal.create(journal.path)
            result = {'status': 'initialized', 'mode': 'off'}
        elif args.command == 'configure':
            with closing(connect(args.events_db)) as conn:
                registered = conn.execute('SELECT workspace_id FROM workspaces WHERE workspace_id=?', (args.workspace,)).fetchone()
                if registered is None:
                    raise ValueError('workspace_unregistered')
                with registered_workspace_authority_lease(args.events_db, conn, args.workspace) as state:
                    if state is not None and state.phase != 'active':
                        raise ValueError('administratively_inactive')
                    generation = journal.configure(args.workspace, args.mode, args.model_digest, args.threshold)
            result = {'status': 'configured', 'mode': args.mode, 'generation': generation}
        elif args.command == 'history':
            result = {'records': journal.history(args.workspace)}
        else:
            try:
                from research.flow_forecast.runtime_worker import serve
            except ImportError:
                raise ValueError('worker_requires_source_checkout') from None
            result = serve(args.events_db, args.model, seconds=args.seconds)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception:
        print('ToolUseProxy: 予測機能の操作に失敗しました。DB・project・モデル・引数を確認してください。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
