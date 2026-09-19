from copy import deepcopy
import json
import uuid

import pytest

from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.call_history import summarize
from hook_monitor.evaluation.flow_lab.controller import validate_state
from hook_monitor.evaluation.flow_lab.generation_evidence import capture
from hook_monitor.evaluation.flow_lab.preflight import LabError
from test_flow_lab_controller import Provider, context as context, proposal, run


class MeteredProvider(Provider):
    def propose(self, feedback, **limits):
        self.last_evidence = None
        value = super().propose(feedback, **limits)
        self.last_evidence = capture(
            events=json.dumps({'type': 'turn.completed', 'usage': {
                'input_tokens': 10, 'cached_input_tokens': 2, 'output_tokens': 3}}).encode(),
            prompt=b'synthetic', proposal=Proposal.parse(value), model=self.model_id,
            cli_version='codex-cli 0.153.4', call_id=uuid.uuid4().hex, elapsed_ms=1)
        return value


@pytest.mark.parametrize('last,status', [
    ({'status': 'complete', 'actions': []}, 'completed'),
    ({'status': 'refused', 'actions': []}, 'model_refused'),
    (proposal(), 'repeated_proposal'),
])
def test_all_responses_count_including_non_trial_calls(context, last, status):
    result = run(context, MeteredProvider([proposal(), last]))
    assert result['status'] == status
    saved = context[0].read()
    validate_state(saved, context[4])
    assert len(saved['plans']) == 1
    assert len(saved['call_records']) == 2
    costs = result['generation_costs']
    assert costs['token_totals_complete'] is True
    assert costs['known_token_totals'] == {'input_tokens': 20, 'cached_input_tokens': 4, 'output_tokens': 6}
    assert costs['provider_cost'] is None


def test_failure_and_retry_preserve_unknown_usage(context):
    first = run(context, MeteredProvider([LabError('model_timeout')]))
    assert first['generation_costs']['failed_calls'] == 1
    assert first['generation_costs']['known_token_totals'] is None
    assert first['generation_costs']['token_totals_complete'] is False
    later = run(context, MeteredProvider([{'status': 'complete', 'actions': []}]))
    costs = later['generation_costs']
    assert costs['charged_calls'] == 2 and costs['calls_without_usage'] == 1
    assert costs['known_token_totals']['input_tokens'] == 10
    assert costs['token_totals_complete'] is False
    validate_state(context[0].read(), context[4])


def test_crash_leaves_pending_record_and_does_not_repeat_call(context):
    class Crashed(Provider):
        def propose(self, feedback, **limits):
            saved = context[0].read()
            assert saved['call_records'][-1]['outcome'] == 'pending'
            assert saved['call_records'][-1]['reply_limit'] == limits['max_bytes']
            raise RuntimeError('synthetic_crash')
    with pytest.raises(RuntimeError, match='synthetic_crash'):
        run(context, Crashed([]))
    saved = context[0].read()
    validate_state(saved, context[4])
    assert summarize(saved)['pending_calls'] == 1
    assert summarize(saved)['call_time_complete'] is False
    result = run(context, Provider([]))
    assert result['status'] == 'model_response_unknown'
    assert result['generation_costs']['charged_calls'] == 1


def test_history_tampering_and_missing_plan_receipt_rejected(context):
    run(context, MeteredProvider([proposal(), {'status': 'complete', 'actions': []}]))
    saved = context[0].read()
    mutations = []
    changed = deepcopy(saved)
    changed['call_records'] = None
    mutations.append(changed)
    changed = deepcopy(saved)
    changed['call_records'].pop()
    mutations.append(changed)
    changed = deepcopy(saved)
    changed['call_records'][0]['reply_limit'] = 1
    mutations.append(changed)
    changed = deepcopy(saved)
    changed['call_records'][0]['generation'] = None
    mutations.append(changed)
    for changed in mutations:
        with pytest.raises(LabError, match='invalid_search_state'):
            validate_state(changed, context[4])
    legacy = deepcopy(saved)
    del legacy['call_records']
    validate_state(legacy, context[4])
    assert summarize(legacy)['call_history_complete'] is False
    assert summarize(legacy)['known_token_totals'] is None


def test_failed_call_can_have_reported_usage_without_an_accepted_proposal(context):
    class FailedWithUsage(Provider):
        def propose(self, *args, **kwargs):
            self.last_execution = capture(
                events=b'{"type":"turn.completed","usage":{"input_tokens":12,"cached_input_tokens":2,"output_tokens":7}}',
                prompt=b'synthetic', proposal=None, model=self.model_id,
                cli_version='codex-cli 0.153.4', call_id=uuid.uuid4().hex, elapsed_ms=1)
            raise LabError('invalid_model_proposal')
    result = run(context, FailedWithUsage([]))
    assert result['status'] == 'invalid_model_proposal'
    assert result['generation_costs']['token_totals_complete'] is True
    assert result['generation_costs']['known_token_totals']['output_tokens'] == 7
    assert context[0].read()['plans'] == []
    assert context[3].guards == 0
    assert context[0].read()['call_records'][0]['generation'] is None
    validate_state(context[0].read(), context[4])
