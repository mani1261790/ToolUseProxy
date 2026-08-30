from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
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


def test_session_start_records_current_runtime_attestation_when_configured(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "plugin-data"
    data_dir.mkdir()
    database = data_dir / "events.db"
    store = EventStore(database)
    store.initialize()
    context = resolve_workspace(
        str(workspace),
        str(workspace),
        discovered_by="test",
    )
    store.register_workspace(context)

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
        input=json.dumps(
            {
                "hook_event_name": "SessionStart",
                "session_id": "attested-session",
                "cwd": str(workspace),
            }
        ),
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "SessionStart"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT session_id, payload_json
            FROM events
            WHERE phase = 'session_start'
            """
        ).fetchone()
    assert row is not None
    assert row[0] == "attested-session"
    attestation = json.loads(row[1])["_tooluseproxy_runtime"]
    assert set(attestation) == {
        "plugin_version",
        "runtime_version",
        "hooks_sha256",
    }
    assert len(attestation["hooks_sha256"]) == 64


def test_coverage_never_claims_hosted_tool_enforcement() -> None:
    coverage = codex_enforcement_coverage()

    assert coverage == {
        "scope": "partial",
        "hook_visible_local_tool_subscription": "all",
        "active_workspace_pre_execution_policy": "adapter_or_conservative_unknown",
        "local_file_mutations": "observed_not_external_sink",
        "hosted_tools": "not_interceptable",
        "hosted_tool_mitigation": "session_and_subagent_developer_context",
        "hosted_tool_pre_execution_block": False,
        "write_stdin_continuations": "not_rechecked",
        "programmatic_nested_tools": "unverified",
        "specialized_tool_paths": "unverified",
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
    assert coverage["write_stdin_continuations"] == "not_rechecked"
    assert coverage["programmatic_nested_tools"] == "unverified"
    assert coverage["specialized_tool_paths"] == "unverified"


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
