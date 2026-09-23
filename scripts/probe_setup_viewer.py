"""Exercise fresh Setup, real Hook judgments, and local viewer receipt in isolation.

Uses the configured Codex model with synthetic data. Does not reset a user's project,
change Plugin enablement, or claim that Desktop's panel API was exercised.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request


def main():
    repository = Path(__file__).resolve().parents[1]
    base = Path(tempfile.mkdtemp(prefix='tup-setup-hook-proof-')).resolve()
    workspace, data = base/'workspace', base/'data'
    workspace.mkdir()
    data.mkdir()
    (workspace/'research_notes.md').write_text('Fictional confidential coefficient 0.7314.\n')
    argv = ['sh', str(repository/'hooks/run_cli.sh'), 'setup', '--workspace', str(workspace),
            '--data-dir', str(data), '--accept-judge-data', '--protect', 'research_notes.md', '--json']
    environment = dict(os.environ, PYTHONPATH=str(repository))
    def hook(phase, payload):
        invocation = [sys.executable, '-c',
            'from pathlib import Path; import sys; from tooluseproxy.engine.hook import run; '
            'raise SystemExit(run(sys.argv[1],Path(sys.argv[2])))', phase, str(data/'events.db')]
        result = subprocess.run(invocation, input=json.dumps(payload), text=True,
                                capture_output=True, env=environment, timeout=600, check=True)
        return json.loads(result.stdout)
    try:
        output = subprocess.check_output(argv, text=True, env=environment)
        setup = json.loads(output)
        assert setup['status'] == 'configured_unverified'
        payload = dict(cwd=str(workspace), session_id='setup-viewer-proof', tool_use_id='setup',
                       tool_name='Bash', tool_input={'command':shlex.join(argv)}, tool_response=output)
        assert hook('post-tool-use', payload) == {}
        url = setup['viewer']['url']
        payload = dict(cwd=str(workspace), session_id='setup-viewer-proof', tool_use_id='open',
                       tool_name='mcp__codex_app__open_in_codex',
                       tool_input={'target':{'type':'browser','url':url},'placement':'right'})
        permission = hook('pre-tool-use', payload)
        report = dict(hook_response=permission, desktop_panel_exercised=False)
        with sqlite3.connect(data/'events.db') as conn:
            report['decisions'] = conn.execute('SELECT action,reason FROM semantic_flow_decisions ORDER BY rowid').fetchall()
        if permission == {}:
            with urllib.request.urlopen(url, timeout=5) as response:
                report['viewer_http_status'] = response.status
        (base/'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(json.dumps(report, ensure_ascii=False), flush=True)
        assert permission == {} and report['viewer_http_status'] == 200
    finally:
        # Only processes whose exact argv identifies this isolated DB.
        processes = subprocess.check_output(['ps','-axo','pid=,command='], text=True)
        for line in processes.splitlines():
            pid, _, command = line.strip().partition(' ')
            try:
                tokens = shlex.split(command)
                if str(data/'events.db') in tokens and any(t in tokens for t in ('tooluseproxy.app', 'tooluseproxy.engine.worker')):
                    os.kill(int(pid), signal.SIGTERM)
            except (ValueError, ProcessLookupError, PermissionError):
                pass
        print(json.dumps({'evidence_directory':str(base)}), flush=True)


if __name__ == '__main__':
    main()
