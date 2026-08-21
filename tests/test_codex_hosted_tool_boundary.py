from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tooluseproxy.integrations.codex import codex_enforcement_coverage


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_session_start_injects_value_free_hosted_tool_boundary(tmp_path: Path) -> None:
    data_dir = tmp_path / "plugin-data"
    sentinel = "MUST.NOT.APPEAR.IN.SESSION.CONTEXT.71D1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooluseproxy",
            "hook",
            "session-start",
            "--data-dir",
            str(data_dir),
        ],
        cwd=REPO_ROOT,
        input=json.dumps({"hook_event_name": "SessionStart", "secret": sentinel}),
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]
    assert hook_output["hookEventName"] == "SessionStart"
    context = hook_output["additionalContext"]
    assert "WebSearch" in context
    assert "登録された保護対象" in context
    assert "実行前に検査・遮断できません" in context
    assert "hosted toolを呼ばず" in context
    assert sentinel not in result.stdout
    assert not data_dir.exists()


def test_coverage_never_claims_hosted_tool_enforcement() -> None:
    coverage = codex_enforcement_coverage()

    assert coverage == {
        "scope": "partial",
        "local_function_tools": "pre_execution_hook_enforced",
        "hosted_tools": "not_interceptable",
        "hosted_tool_mitigation": "session_and_subagent_developer_context",
        "hosted_tool_pre_execution_block": False,
    }


def test_status_exposes_partial_enforcement_coverage(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooluseproxy",
            "status",
            "--workspace",
            str(workspace),
            "--data-dir",
            str(tmp_path / "plugin-data"),
            "--json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    coverage = json.loads(result.stdout)["enforcement_coverage"]
    assert coverage["scope"] == "partial"
    assert coverage["hosted_tools"] == "not_interceptable"
    assert coverage["hosted_tool_pre_execution_block"] is False


def test_plugin_registers_session_start_before_tool_hooks() -> None:
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text())

    assert list(hooks["hooks"]) == [
        "SessionStart",
        "SubagentStart",
        "PreToolUse",
        "PostToolUse",
        "Stop",
    ]
    command = hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert command.endswith('hooks/run_hook.sh\" session-start')


def test_subagent_start_repeats_the_same_hosted_tool_boundary(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooluseproxy",
            "hook",
            "subagent-start",
            "--data-dir",
            str(tmp_path / "plugin-data"),
        ],
        cwd=REPO_ROOT,
        input=json.dumps({"hook_event_name": "SubagentStart"}),
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "SubagentStart"
    assert "WebSearch" in output["additionalContext"]
