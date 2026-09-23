#!/usr/bin/env python3
"""Bound the model-driven Hook. A timeout is not a leak finding."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, Sequence

PRE_TOOL_CHILD_TIMEOUT_SECONDS = 720.0


def run_child(
    command: Sequence[str],
    *,
    phase: str,
    stdin: BinaryIO,
    stdout: BinaryIO,
    timeout_seconds: float = PRE_TOOL_CHILD_TIMEOUT_SECONDS,
) -> int:
    try:
        with subprocess.Popen(
            list(command), stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=os.name == "posix",
        ) as child:
            try:
                output, _ = child.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                # Terminate descendants that share the Hook group. The Codex
                # transport owns a separate group and its own bounded timeout.
                if os.name == "posix":
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    child.kill()
                child.communicate()
                raise
            completed = subprocess.CompletedProcess(command, child.returncode, output)
    except (subprocess.TimeoutExpired, OSError) as error:
        reason = "semantic_watchdog_timeout" if isinstance(error, subprocess.TimeoutExpired) else "semantic_start_failed"
        return pending_output(stdout, phase, reason)
    if phase == "pre-tool-use":
        if completed.returncode:
            return pending_output(stdout, phase, "semantic_child_failed")
        try:
            value = json.loads(completed.stdout)
            if not isinstance(value, dict):
                raise ValueError()
            if value:
                details = value["hookSpecificOutput"]
                if (details.get("hookEventName") != "PreToolUse"
                        or details.get("permissionDecision") != "deny"):
                    raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError):
            return pending_output(stdout, phase, "semantic_child_invalid_response")
    stdout.write(completed.stdout)
    return completed.returncode


def pending_output(stdout, phase, reason):
    output = {}
    if phase == "pre-tool-use":
        output = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "ToolUseProxyは判定完了まで実行を保留しています。"
            "流出検出ではありません。復旧後に再検査してください。（" + reason + "）",
        }}
    stdout.write((json.dumps(output, ensure_ascii=False) + "\n").encode())
    return 0


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3 or arguments[1] != "--data-dir":
        return 2
    root = Path(__file__).resolve().parent
    return run_child(
        [sys.executable, str(root / "tooluseproxy_plugin.py"), "hook", *arguments],
        phase=arguments[0],
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
    )


if __name__ == "__main__":
    raise SystemExit(main())
