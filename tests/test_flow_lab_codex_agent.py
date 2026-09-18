import json
import stat
import sys

import pytest

from hook_monitor.evaluation.flow_lab.codex_agent import CodexProvider, command_line, parse_events
from hook_monitor.evaluation.flow_lab.preflight import LabError


def events(value):
    return (json.dumps({"type": "item.completed", "item": {
        "type": "agent_message", "text": json.dumps(value),
    }}) + '\n' + json.dumps({"type": "turn.completed"})).encode()


def test_proposal_and_completion_required():
    value = {"status": "complete", "actions": []}
    assert parse_events(events(value), 16384) == value
    with pytest.raises(LabError, match="invalid_model_proposal"):
        parse_events(events(value).splitlines()[0], 16384)
    with pytest.raises(LabError, match="model_response_limit"):
        parse_events(events(value), 2)


@pytest.mark.parametrize("kind", ["command_execution", "file_change", "mcp_tool_call",
                                   "request_user_input", "web_search"])
def test_tool_output_is_not_a_proposal(kind):
    payload = {"type": "item.completed", "item": {"type": kind, "text": "PRIVATE"}}
    with pytest.raises(LabError, match="model_tool_request_rejected"):
        parse_events(json.dumps(payload).encode(), 16384)


def test_cli_has_no_hook_trust_or_admin_bypass(tmp_path):
    args = command_line("codex", tmp_path, "synthetic-model")
    assert not any("bypass" in arg for arg in args)
    assert args[args.index("-s") + 1] == "read-only"
    for feature in ("shell_tool", "plugins", "hooks", "browser_use", "computer_use", "apps"):
        assert args[args.index(feature) - 1] == "--disable"
    assert "--ignore-user-config" in args
    assert "approval_policy=\"never\"" in args


def executable(tmp_path, body, version="codex-cli 0.153.4"):
    path = tmp_path / "codex-fixture"
    path.write_text(f'''#!{sys.executable}
import sys, time
if '--version' in sys.argv:
    print({version!r})
else:
    sys.stdin.read()
    {body}
''')
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_real_process_adapter_with_synthetic_cli(tmp_path):
    value = {"status": "complete", "actions": []}
    provider = CodexProvider("synthetic-model", executable=executable(
        tmp_path, f"print({events(value).decode()!r})"))
    assert provider.propose([], task_mode="adaptive_search", timeout=2, max_bytes=16384) == value


def test_real_process_timeout(tmp_path):
    provider = CodexProvider("synthetic-model", executable=executable(tmp_path, "time.sleep(5)"))
    with pytest.raises(LabError, match="model_timeout"):
        provider.propose([], task_mode="adaptive_search", timeout=0.05, max_bytes=16384)


def test_unverified_cli_version_is_not_run(tmp_path):
    with pytest.raises(LabError, match="codex_version_requires_capability_check"):
        CodexProvider("synthetic-model", executable=executable(tmp_path, "raise Exception", "future"))


def test_large_cli_output_is_stopped(tmp_path):
    provider = CodexProvider("synthetic-model", executable=executable(
        tmp_path, "print('x' * (2 * 1024 * 1024))"))
    with pytest.raises(LabError, match="model_response_limit"):
        provider.propose([], task_mode="adaptive_search", timeout=2, max_bytes=16384)


@pytest.mark.parametrize("diagnostic,reason", [
    ({"code": "insufficient_quota", "message": "PRIVATE"}, "model_quota_exhausted"),
    ({"message": "Authentication failed: PRIVATE"}, "model_auth_required"),
    ({"message": "PRIVATE"}, "model_unavailable"),
])
def test_provider_error_is_classified_without_printing_diagnostic(diagnostic, reason):
    with pytest.raises(LabError, match="^" + reason + "$"):
        parse_events(json.dumps({"type": "turn.failed", "error": diagnostic}).encode(), 16384)
