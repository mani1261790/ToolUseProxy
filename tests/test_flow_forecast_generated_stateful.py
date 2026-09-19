"""Synthetic provider receipts below test bindings, not real model evidence."""
from copy import deepcopy
import json
import uuid

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.codex_agent import proposal_prompt
from hook_monitor.evaluation.flow_lab.generation_evidence import capture
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import generated_stateful as module
from research.flow_forecast import stateful_collection
from test_flow_lab_task_assignment import binding
from test_flow_forecast_stateful_collection import lab as lab


class Provider:
    model_id = 'fixture-model'

    def __init__(self, value=None):
        self.value = value or {'status': 'propose', 'actions': [{'source': 'public', 'encoding': 'base64'}]}
        self.calls = 0
        self.last_evidence = self.last_execution = None

    def propose(self, feedback, *, task_mode, task_context, **kwargs):
        self.calls += 1
        assert feedback == []
        receipt = dict(events=b'{"type":"turn.completed","usage":{"input_tokens":20,"cached_input_tokens":0,"output_tokens":5}}',
                       prompt=proposal_prompt([], task_mode, task_context).encode(), model=self.model_id,
                       cli_version='codex-cli 0.153.4', call_id=uuid.uuid4().hex, elapsed_ms=1)
        self.last_evidence = capture(**receipt, proposal=Proposal.parse(self.value))
        self.last_execution = capture(**receipt, proposal=None)
        return self.value


def test_pretrial_assignment_and_call_reservation_precede_only_proposal(tmp_path):
    output = tmp_path / 'prepared'
    assignment = binding()
    class Inspecting(Provider):
        def propose(self, *args, **kwargs):
            assert json.loads((output / 'request.json').read_text())['assignment'] == assignment
            assert json.loads((output / 'call-reservation.json').read_text())['outcome'] == 'pending'
            return super().propose(*args, **kwargs)
    provider = Inspecting()
    result = module.prepare(assignment, provider, output)
    assert provider.calls == 1 and result['status'] == 'prepared'
    frozen = module.load(output)
    assert frozen['plan'] == {'schema': 1, 'source': 'public', 'operations': ['read', 'encode', 'save', 'send']}
    assert frozen['generation']['resolved_model_verified'] is False
    assert result['costs']['known_token_totals']['input_tokens'] == 20
    assert result['costs']['provider_cost'] is None
    with pytest.raises(FileExistsError):
        module.prepare(assignment, provider, output)
    assert provider.calls == 1


@pytest.mark.parametrize('value', [
    {'status': 'refused', 'actions': []},
    {'status': 'complete', 'actions': []},
    {'status': 'propose', 'actions': [{'source': 'public', 'encoding': 'plain'}] * 2},
    {'status': 'propose', 'actions': [{'source': 'public', 'encoding': 'plain', 'representation': 'split', 'client': 'urllib'}]},
])
def test_unsupported_or_refused_proposals_keep_cost_without_retry(tmp_path, value):
    output = tmp_path / 'prepared'
    provider = Provider(value)
    result = module.prepare(binding(), provider, output)
    assert provider.calls == 1 and result['status'] == 'not_prepared'
    assert result['costs']['charged_calls'] == 1 and result['costs']['calls_with_usage'] == 1
    assert not (output / 'generated-plan.json').exists()
    with pytest.raises(FileExistsError):
        module.prepare(binding(), provider, output)


def test_timeout_and_interruption_leave_charged_call_and_no_seal(tmp_path):
    for error in (LabError('model_timeout'), KeyboardInterrupt()):
        class Failing(Provider):
            def propose(self, *args, **kwargs):
                raise error
        output = tmp_path / type(error).__name__
        if isinstance(error, KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                module.prepare(binding(), Failing(), output)
        else:
            module.prepare(binding(), Failing(), output)
        result = json.loads((output / 'call-result.json').read_text())
        assert result['status'] == 'not_prepared'
        assert result['costs']['charged_calls'] == result['costs']['failed_calls'] == 1
        assert result['costs']['token_totals_complete'] is False
        assert result['costs']['known_token_totals'] is None
        assert not (output / 'generated-plan.json').exists()


@pytest.mark.parametrize('field', ['assignment', 'proposal', 'plan', 'execution', 'costs', 'request'])
def test_posthoc_changes_are_rejected_even_if_outer_hash_is_recomputed(tmp_path, field):
    directory = tmp_path / 'prepared'
    module.prepare(binding(), Provider(), directory)
    frozen = module.load(directory)
    if field in {'assignment', 'proposal', 'plan'}:
        if field == 'assignment':
            frozen[field]['catalog']['designs'][0]['objective'] = 'changed after generation'
        elif field == 'proposal':
            frozen[field]['actions'][0]['encoding'] = 'plain'
        else:
            frozen[field]['source'] = 'protected'
        frozen['prepared_sha'] = digest({k: v for k, v in frozen.items() if k != 'prepared_sha'})
        (directory / 'generated-plan.json').write_text(canonical(frozen))
    elif field in {'execution', 'costs'}:
        result = json.loads((directory / 'call-result.json').read_text())
        if field == 'execution':
            result['call']['execution']['call_id'] = uuid.uuid4().hex
        else:
            result['costs']['charged_calls'] = 0
        (directory / 'call-result.json').write_text(canonical(result))
    else:
        (directory / 'request.json').write_text('{}')
    with pytest.raises(ForecastDataError):
        module.load(directory)


def test_model_receipt_prompt_must_match_pretrial_assignment(tmp_path):
    class WrongPrompt(Provider):
        def propose(self, *args, **kwargs):
            value = super().propose(*args, **kwargs)
            self.last_evidence['prompt_sha'] = '0' * 64
            return value
    result = module.prepare(binding(), WrongPrompt(), tmp_path / 'prepared')
    assert result['status'] == 'not_prepared'
    assert not (tmp_path / 'prepared/generated-plan.json').exists()


def test_sealed_generation_is_bound_before_stateful_dispatch(lab, tmp_path):
    directory = tmp_path / 'prepared'
    from hook_monitor.evaluation.flow_lab.task_assignment import prepare as assignment_prepare
    base = binding()
    assignment = assignment_prepare(base['catalog'], {k: v.encode() for k, v in base['origins'].items()},
                                    base['design_id'], completion={
                                        'schema': 1, 'kind': 'public_delivery', 'deliveries': 1, 'encoding': 'base64'})
    module.prepare(assignment, Provider(), directory)
    frozen = module.load(directory)
    output = tmp_path / 'capture'
    result = stateful_collection.run(tmp_path, frozen['plan'], output, generation=frozen)
    intent = json.loads((output / 'intent.json').read_text())
    assert intent['generator_evidence'] == frozen
    assert result['prepared_generation_sha'] == frozen['prepared_sha']
    assert result['source_generation_calls'] == 1 and result['new_model_calls'] == 0
    assert result['generator_model_verified'] is False
    assert result['independent_new_task_count'] == 0
    assert all(c['task_completion']['status'] == 'achieved' for c in result['conditions'])
    assert all(c['task_completion']['observed_public_deliveries'] == 1 for c in result['conditions'])
    changed = deepcopy(frozen['plan'])
    changed['source'] = 'protected'
    with pytest.raises(ForecastDataError, match='generated_plan_mismatch'):
        stateful_collection.run(tmp_path, changed, tmp_path / 'other', generation=frozen)
    assert not (tmp_path / 'other').exists()


def test_invalid_implementation_identity_is_rejected_before_trial(tmp_path):
    directory = tmp_path / 'prepared'
    module.prepare(binding(), Provider(), directory)
    value = module.load(directory)
    value['implementation_sha'] = None
    value['prepared_sha'] = digest({k: v for k, v in value.items() if k != 'prepared_sha'})
    with pytest.raises(ForecastDataError):
        module.validate(value)
