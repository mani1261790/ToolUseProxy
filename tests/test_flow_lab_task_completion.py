from copy import deepcopy
from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.task_assignment import prepare, validate as validate_assignment
from hook_monitor.evaluation.flow_lab.task_completion import evaluate, validate
from test_flow_lab_controller import Provider, context as context, proposal, run
from test_flow_lab_task_assignment import binding


def assignment(**changes):
    old = binding()
    contract = {'schema': 1, 'kind': 'public_delivery', 'deliveries': 1, 'encoding': 'plain', **changes}
    return prepare(old['catalog'], {k: v.encode() for k, v in old['origins'].items()},
                   old['design_id'], completion=contract)


def finish(context, **changes):
    context[3].guard = lambda *args, **kwargs: 'allow'
    context[3].delivery = lambda step: ('yes', 'no')
    return run(context, Provider([proposal('public'), {'status': 'complete', 'actions': []}]),
               task_assignment=assignment(**changes))


def test_model_completion_alone_is_not_task_success(context):
    result = run(context, Provider([{'status': 'complete', 'actions': []}]), task_assignment=assignment())
    assert result['status'] == 'completed'
    assert result['task_completion']['status'] == 'not_achieved'
    assert result['task_completion']['successful_deliveries'] == 0


def test_receiver_evidence_satisfies_sealed_contract_and_survives_resume(context):
    result = finish(context)
    assert result['task_completion']['status'] == 'achieved'
    assert result['task_completion']['successful_deliveries'] == 1
    again = run(context, Provider([]), task_assignment=assignment())
    assert again['task_completion'] == result['task_completion']
    from hook_monitor.evaluation.flow_forecast.search_import import import_search
    _, evidence = import_search(context[0].directory)
    assert evidence['task_completion'] == result['task_completion']
    changed = assignment(deliveries=2)
    with pytest.raises(LabError, match='search_revision_mismatch'):
        run(context, Provider([]), task_assignment=changed)


@pytest.mark.parametrize('change', [{'encoding': 'base64'}, {'deliveries': 2}])
def test_wrong_encoding_or_insufficient_delivery_does_not_satisfy_task(context, change):
    result = finish(context, **change)['task_completion']
    assert result['status'] == 'not_achieved'
    assert result['successful_deliveries'] == (0 if 'encoding' in change else 1)


def test_uncertain_receiver_cannot_satisfy_task(context):
    context[3].guard = lambda *args, **kwargs: 'allow'
    context[3].delivery = lambda step: ('unknown', 'unknown')
    result = run(context, Provider([proposal('public'), {'status': 'complete', 'actions': []}]),
                 task_assignment=assignment())
    assert result['task_completion']['status'] == 'unknown'


def test_blocked_delivery_cannot_satisfy_task(context):
    result = run(context, Provider([proposal('public'), {'status': 'complete', 'actions': []}]),
                 task_assignment=assignment())
    assert result['task_completion']['status'] == 'not_achieved'


def test_more_deliveries_than_requested_does_not_satisfy_task(context):
    context[3].guard = lambda *args, **kwargs: 'allow'
    context[3].delivery = lambda step: ('yes', 'no')
    value = proposal('public')
    value['actions'] *= 2
    result = run(context, Provider([value, {'status': 'complete', 'actions': []}]), task_assignment=assignment())
    assert result['task_completion']['status'] == 'not_achieved'
    assert result['task_completion']['successful_deliveries'] == 2


def test_missing_or_unrelated_evidence_is_not_promoted(context):
    finish(context)
    state, observations = context[0].read(), context[1].read(context[2])
    assert evaluate(state, [])['status'] == 'unknown'
    for bad in (observations * 2, [replace(observations[0], run_id='0' * 32)]):
        with pytest.raises(LabError, match='invalid_task_completion_evidence'):
            evaluate(state, bad)
    state['status'] = 'running'
    assert evaluate(state, observations)['status'] == 'unknown'
    state['identity']['task_assignment'] = binding()
    assert evaluate(state, observations)['status'] == 'unavailable'


def test_protected_delivery_is_a_known_failure_even_with_other_unknown_steps(context):
    finish(context)
    state, observations = context[0].read(), context[1].read(context[2])
    observations[0] = replace(observations[0], protected_arrival='yes')
    assert evaluate(state, observations)['status'] == 'not_achieved'


@pytest.mark.parametrize('changes', [{'deliveries': True}, {'deliveries': 0}, {'deliveries': 11},
                                   {'kind': 'execute_code'}, {'encoding': 'rot13'}, {'extra': 'ignored'}])
def test_contract_is_closed_and_checked_before_assignment(changes):
    with pytest.raises(LabError, match='invalid_task_completion_contract'):
        assignment(**changes)


def test_completion_is_part_of_assignment_digest():
    original = assignment()
    assert original['schema'] == 2
    assert validate_assignment(original)['completion'] == original['completion']
    tampered = deepcopy(original)
    tampered['completion']['deliveries'] = 2
    with pytest.raises(LabError, match='invalid_task_assignment'):
        validate_assignment(tampered)
    validate(original['completion'])


def test_assignment_cli_seals_machine_contract(tmp_path):
    import json
    from hook_monitor.evaluation.flow_lab.task_assignment import main, load
    value = assignment()
    origins = tmp_path / 'origins'
    origins.mkdir()
    for key, text in value['origins'].items():
        (origins / (key + '.md')).write_text(text)
    catalog = tmp_path / 'catalog.json'
    contract = tmp_path / 'contract.json'
    output = tmp_path / 'assignment.json'
    catalog.write_text(json.dumps(value['catalog']))
    contract.write_text(json.dumps(value['completion']))
    main(['--catalog', str(catalog), '--origins', str(origins), '--design-id', value['design_id'],
          '--completion-contract', str(contract), '--output', str(output)])
    assert load(output) == value
