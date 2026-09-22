#!/usr/bin/env python3
"""Bound the model-driven Hook. A timeout is not a leak finding."""

from __future__ import annotations

import json
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
        completed = subprocess.run(
            list(command),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        output = {}
        if phase == "pre-tool-use":
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": "ToolUseProxyの判定が時間切れになりました。流出検出ではありません。"
                    "警告して継続しますが、安全確認は未完了です。（semantic_watchdog_timeout）",
                }
            }
        stdout.write((json.dumps(output, ensure_ascii=False) + "\n").encode())
        return 0
    stdout.write(completed.stdout)
    return completed.returncode


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
