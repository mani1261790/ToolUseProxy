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


def test_success_records_requested_model_and_usage_without_claiming_resolved_version(tmp_path):
    from hook_monitor.evaluation.flow_lab.generation_evidence import proposal_sha
    from hook_monitor.evaluation.flow_lab.agent import Proposal
    value = {"status": "propose", "actions": [{"source": "public", "encoding": "plain"}]}
    wire = events(value).decode().replace('"type": "turn.completed"',
        '"type": "turn.completed", "usage": {"input_tokens": 20, "cached_input_tokens": 10, "output_tokens": 8}')
    wire = json.dumps({'type': 'thread.started', 'thread_id': 'synthetic-thread'}) + '\n' + wire
    provider = CodexProvider('synthetic-model', executable=executable(tmp_path, f'print({wire!r})'))
    assert provider.propose([], task_mode='benign_task', timeout=2, max_bytes=16384) == value
    evidence = provider.last_evidence
    assert evidence['requested_model'] == 'synthetic-model'
    assert evidence['resolved_model'] is None and evidence['resolved_model_verified'] is False
    assert evidence['usage']['output_tokens'] == 8
    assert evidence['proposal_sha'] == proposal_sha(Proposal.parse(value))
    assert len(evidence['thread_sha']) == 64
    assert 'synthetic-thread' not in json.dumps(evidence)
    first = evidence['call_id']
    provider.propose([], task_mode='benign_task', timeout=2, max_bytes=16384)
    assert provider.last_evidence['call_id'] != first
    with pytest.raises(LabError):
        provider.propose([], task_mode='invalid', timeout=2, max_bytes=16384)
    assert provider.last_evidence is None


@pytest.mark.parametrize('usage', [
    {'input_tokens': True, 'cached_input_tokens': 0, 'output_tokens': 1},
    {'input_tokens': 1, 'cached_input_tokens': 2, 'output_tokens': 1},
    {'input_tokens': 1, 'cached_input_tokens': 0, 'output_tokens': -1},
])
def test_invalid_usage_cannot_be_recorded_as_cost(usage):
    from hook_monitor.evaluation.flow_lab.generation_evidence import capture
    from hook_monitor.evaluation.flow_lab.agent import Proposal
    value = {'status': 'complete', 'actions': []}
    wire = json.dumps({'type': 'turn.completed', 'usage': usage}).encode()
    with pytest.raises(LabError, match='invalid_generation_evidence'):
        capture(events=wire, prompt=b'synthetic', proposal=Proposal.parse(value),
                model='synthetic-model', cli_version='codex-cli 0.153.4', call_id='a' * 32, elapsed_ms=1)


def test_invalid_proposal_preserves_usage_but_never_becomes_accepted(tmp_path):
    wire = events({'PRIVATE': 'invalid proposal'}).decode().replace(
        '"type": "turn.completed"',
        '"type": "turn.completed", "usage": {"input_tokens": 12, "cached_input_tokens": 2, "output_tokens": 7}')
    provider = CodexProvider('synthetic-model', executable=executable(tmp_path, f'print({wire!r})'))
    with pytest.raises(LabError, match='invalid_model_proposal'):
        provider.propose([], task_mode='benign_task', timeout=2, max_bytes=16384)
    assert provider.last_evidence is None
    receipt = provider.last_execution
    assert receipt['proposal_sha'] is None
    assert receipt['usage']['output_tokens'] == 7
    assert 'PRIVATE' not in json.dumps(receipt)
    with pytest.raises(LabError):
        provider.propose([], task_mode='invalid', timeout=2, max_bytes=16384)
    assert provider.last_execution is None


def test_incomplete_usage_remains_unknown_even_when_proposal_failed(tmp_path):
    wire = events({'status': 'invalid', 'actions': []}).decode().replace(
        '"type": "turn.completed"', '"type": "turn.completed", "usage": {"input_tokens": 12}')
    provider = CodexProvider('synthetic-model', executable=executable(tmp_path, f'print({wire!r})'))
    with pytest.raises(LabError, match='invalid_model_proposal'):
        provider.propose([], task_mode='benign_task', timeout=2, max_bytes=16384)
    assert provider.last_execution is None


@pytest.mark.parametrize('wire,stage', [
    (b'private invalid event', 'event_or_text_invalid'),
    (events({'status': 'invalid', 'actions': []}), 'proposal_schema_invalid'),
    (b'{"type":"turn.completed"}', 'message_count_invalid'),
    (b'{"type":"item.completed","item":{"type":"agent_message","text":"private non-json"}}\n{"type":"turn.completed"}', 'proposal_json_invalid'),
])
def test_closed_validation_stage_contains_no_response_text(wire, stage):
    with pytest.raises(LabError) as caught:
        parse_events(wire, 16384)
    assert str(caught.value) == 'invalid_model_proposal'
    assert caught.value.validation_stage == stage
