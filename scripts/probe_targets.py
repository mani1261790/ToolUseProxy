"""Real-model transmission description using fictional payloads; never sends them."""
import json
import tempfile
from pathlib import Path

from tooluseproxy.engine.journal import Journal, event_from
from tooluseproxy.engine.judge import CodexSemanticJudge
from tooluseproxy.engine.targets import inspect_transmission


def main():
    with tempfile.TemporaryDirectory(prefix='tup-targets-') as directory:
        root = Path(directory).resolve()
        (root / 'message.txt').write_text('Fictional greeting for a transmission test.')
        store = Journal(root / 'events.db')
        store.initialize()
        cases = [
            ('inline', 'HTTP POST', {'url': 'https://example.invalid/receive', 'body': 'Fictional greeting for a transmission test.'}),
            ('reference', 'Bash', {'command': 'curl --data-binary @message.txt https://example.invalid/receive'}),
        ]
        for name, tool, tool_input in cases:
            event = event_from('pre_tool_use', dict(cwd=str(root), session_id='fixture', tool_use_id=name,
                 tool_name=tool, tool_input=tool_input), str(root))
            store.record(event)
            _, result, _ = inspect_transmission(store, event, CodexSemanticJudge(timeout=60))
            contains = any(b'Fictional greeting' in part.content for part in result.parts)
            print(json.dumps(dict(case=name, coverage=result.coverage, payload_found=contains,
                                  needs=[need.reason for need in result.needs])), flush=True)
            if not contains or result.coverage != 'complete':
                raise SystemExit('target_probe_mismatch')


if __name__ == '__main__':
    main()
