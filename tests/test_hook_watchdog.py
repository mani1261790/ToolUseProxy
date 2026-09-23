from __future__ import annotations

import io
import json
import sys
import tempfile
import time
from pathlib import Path

from tooluseproxy_hook_watchdog import run_child


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_failed_child_cannot_release_a_pending_call() -> None:
    expected = b'{"result":"ok"}\n'
    stdout = io.BytesIO()
    with tempfile.TemporaryFile() as stdin:
        stdin.write(b"input")
        stdin.seek(0)
        result = run_child(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(%r); raise SystemExit(3)" % expected,
            ],
            phase="pre-tool-use",
            stdin=stdin,
            stdout=stdout,
            timeout_seconds=1.0,
        )

    assert result == 0
    details = json.loads(stdout.getvalue())["hookSpecificOutput"]
    assert details["permissionDecision"] == "deny"
    assert "semantic_child_failed" in details["permissionDecisionReason"]


def test_timeout_retains_execution_without_claiming_a_leak() -> None:
    sentinel = "WATCHDOG.SLOW.CHILD.MUST.NOT.LEAK"
    stdout = io.BytesIO()
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdin:
        stdin.write(b"protected input is never echoed")
        stdin.seek(0)
        result = run_child(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time; "
                    f"sys.stdout.write({sentinel!r}); sys.stdout.flush(); time.sleep(5)"
                ),
            ],
            phase="pre-tool-use",
            stdin=stdin,
            stdout=stdout,
            timeout_seconds=0.05,
        )

    elapsed = time.monotonic() - started
    output = json.loads(stdout.getvalue())
    details = output["hookSpecificOutput"]
    assert result == 0
    assert elapsed < 1.0
    assert details["hookEventName"] == "PreToolUse"
    assert details["permissionDecision"] == "deny"
    assert "semantic_watchdog_timeout" in details["permissionDecisionReason"]
    assert sentinel not in stdout.getvalue().decode("utf-8")


def test_pre_tool_host_timeout_exceeds_internal_deadline() -> None:
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    pre_tool_timeout = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"]

    assert pre_tool_timeout == 900


def test_both_launchers_invoke_the_watchdog() -> None:
    for launcher in ("hooks/run_hook.sh", "hooks/run_hook.cmd"):
        content = (REPO_ROOT / launcher).read_text(encoding="utf-8")
        assert "tooluseproxy_hook_watchdog.py" in content
        assert 'tooluseproxy_plugin.py" hook' not in content


def test_invalid_or_empty_pre_output_cannot_release_execution():
    for response in ('', 'not-json', 'null', '{"hookSpecificOutput":{"additionalContext":"warning"}}'):
        stdout = io.BytesIO()
        with tempfile.TemporaryFile() as stdin:
            result = run_child([sys.executable, '-c', f'print({response!r})'],
                               phase='pre-tool-use', stdin=stdin, stdout=stdout)
        details = json.loads(stdout.getvalue())['hookSpecificOutput']
        assert result == 0 and details['permissionDecision'] == 'deny'
        assert 'semantic_child_invalid_response' in details['permissionDecisionReason']


def test_explicit_noop_response_preserves_host_approval_rules():
    stdout = io.BytesIO()
    with tempfile.TemporaryFile() as stdin:
        run_child([sys.executable, '-c', 'print("{}")'], phase='pre-tool-use',
                  stdin=stdin, stdout=stdout)
    assert json.loads(stdout.getvalue()) == {}
