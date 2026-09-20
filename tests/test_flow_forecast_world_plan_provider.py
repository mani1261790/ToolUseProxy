from dataclasses import asdict
import hashlib

import pytest

from hook_monitor.evaluation.flow_lab.codex_agent import parse_events
from hook_monitor.evaluation.flow_lab.generation_evidence import validate
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast.world_plan_provider import Plan, WorldPlanProvider, prompt
from test_flow_lab_codex_agent import events, executable


PLAN = {'status': 'propose', 'operations': ['load', 'compute', 'save', 'send'], 'export': 'public'}


def test_typed_plan_reuses_tool_free_process_and_receipts(tmp_path):
    provider = WorldPlanProvider('fixture-model', executable=executable(tmp_path, f'print({events(PLAN).decode()!r})'))
    result = provider.propose([], task_mode='benign_task', timeout=2, max_bytes=16384, task_context={'world': 'inventory'})
    plan = Plan.parse(result)
    assert plan.executable() and asdict(plan)['export'] == 'public'
    validate(provider.last_evidence, plan, provider.model_id)
    assert provider.last_evidence['prompt_sha'] == hashlib.sha256(prompt([], 'benign_task', {'world': 'inventory'}).encode()).hexdigest()
    assert provider.last_execution['call_id'] == provider.last_evidence['call_id']
    assert provider.last_evidence['resolved_model_verified'] is False


def test_schema_valid_but_incomplete_plan_does_not_execute():
    assert not Plan.parse({**PLAN, 'operations': ['load', 'send']}).executable()
    assert not Plan.parse({'status': 'refused', 'operations': [], 'export': 'public'}).executable()


def test_task_plan_parser_still_rejects_host_tool_events():
    import json
    wire = json.dumps({'type': 'item.completed', 'item': {'type': 'command_execution'}}).encode()
    with pytest.raises(LabError, match='model_tool_request_rejected'):
        parse_events(wire, 16384, validator=Plan.parse)


@pytest.mark.parametrize('value', [{**PLAN, 'command': 'anything'}, {**PLAN, 'operations': ['python']},
                                   {'status': 'refused', 'operations': ['send'], 'export': 'public'}])
def test_plan_cannot_inject_tools_or_code(value):
    with pytest.raises(LabError):
        Plan.parse(value)


def test_prompt_rejects_feedback_and_arbitrary_context():
    with pytest.raises(LabError):
        prompt([{}], 'benign_task', {'world': 'ledger'})
    with pytest.raises(LabError):
        prompt([], 'benign_task', {'world': 'ledger', 'code': 'anything'})
