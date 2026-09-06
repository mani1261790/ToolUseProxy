#!/usr/bin/env python3
"""Bound the Codex Hook child before the host can time it out."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, Sequence


PRE_TOOL_CHILD_TIMEOUT_SECONDS = 7.0


def _deadline_output() -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                "ToolUseProxyの保護判定が制限時間内に完了しませんでした。"
                "（技術情報: hook_deadline_exceeded）"
            ),
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "ToolUseProxyが操作を実行前に止めました。"
                "保護判定が時間内に完了しなかったため、この操作を許可できません。"
                "少し待ってからやり直してください。\n"
                "結果：外部操作は実行されていません。保護対象の内容も表示していません。"
            ),
        }
    }


def run_child(
    command: Sequence[str],
    *,
    phase: str,
    stdin: BinaryIO,
    stdout: BinaryIO,
    timeout_seconds: float = PRE_TOOL_CHILD_TIMEOUT_SECONDS,
) -> int:
    timeout = timeout_seconds if phase == "pre-tool-use" else None
    try:
        completed = subprocess.run(
            list(command),
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if phase == "pre-tool-use":
            rendered = json.dumps(_deadline_output(), ensure_ascii=False) + "\n"
            stdout.write(rendered.encode("utf-8"))
        return 0
    stdout.write(completed.stdout)
    return completed.returncode


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3 or arguments[1] != "--data-dir" or not arguments[2]:
        return 2
    phase = arguments[0]
    plugin_root = Path(__file__).resolve().parent
    command = [
        sys.executable,
        str(plugin_root / "tooluseproxy_plugin.py"),
        "hook",
        phase,
        "--data-dir",
        arguments[2],
    ]
    return run_child(
        command,
        phase=phase,
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
    )


if __name__ == "__main__":
    raise SystemExit(main())
