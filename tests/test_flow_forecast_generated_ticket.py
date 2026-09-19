import json
from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import generated_ticket as module, bfcl_ticket_collection as ticket_collection, bfcl_ticket_import as ticket_import, task_catalog, generator_strata
from research.flow_forecast.ticket_plan_provider import TicketPlanProvider, Plan, prompt, TASK
from test_flow_lab_codex_agent import events, executable
from test_flow_forecast_bfcl_ticket_import import capture, SOURCE
import hashlib
from research.flow_forecast import bfcl_ticket_reference, bfcl_ticket_transport, checked_ticket

PLAN = {'status':'propose','operations':['resolve','query','send'],'export':'public'}


@pytest.fixture(autouse=True)
def source_fixture(monkeypatch,tmp_path):
    (tmp_path/'source.py').write_text(SOURCE)
    for target in (ticket_import,bfcl_ticket_reference,bfcl_ticket_transport,checked_ticket):
        monkeypatch.setattr(target,'SOURCE_SHA',hashlib.sha256(SOURCE.encode()).hexdigest())


def provider(tmp_path, value=PLAN):
    return TicketPlanProvider('fixture-model', executable=executable(tmp_path, f'print({events(value).decode()!r})'))


def test_one_call_plan_seals_receipt_and_costs(tmp_path):
    out = tmp_path/'prepared'
    result = module.prepare(provider(tmp_path), out, timeout=2)
    frozen = module.load(out)
    assert result['status'] == 'prepared' and result['costs']['charged_calls'] == 1
    assert frozen['plan'] == PLAN and frozen['task'] == TASK
    assert frozen['generation']['resolved_model_verified'] is False
    with pytest.raises(FileExistsError):
        module.prepare(provider(tmp_path), out)


@pytest.mark.parametrize('value', [{**PLAN,'operations':['resolve','send']},
                                   {'status':'refused','operations':[],'export':'public'}])
def test_nonexecutable_plan_retains_cost_without_retry(tmp_path, value):
    out = tmp_path/'prepared'
    result = module.prepare(provider(tmp_path,value), out, timeout=2)
    assert result['status'] == 'not_prepared'
    assert result['costs']['charged_calls'] == 1
    assert result['call']['execution'] is not None
    assert not (out/'generated-plan.json').exists()


@pytest.mark.parametrize('name', ['request','implementation','reservation','call-result','generated-plan'])
def test_changed_sealed_artifacts_rejected(tmp_path, name):
    out = tmp_path/'prepared'
    module.prepare(provider(tmp_path), out, timeout=2)
    path = out/(name+'.json')
    value = json.loads(path.read_text())
    if name == 'reservation':
        value['call_id'] = 'different'
    elif name == 'call-result':
        value['costs']['charged_calls'] = 0
    else:
        value['tampered'] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ForecastDataError):
        module.load(out)


def test_capture_binds_generation_before_trials_and_rejects_variant_mismatch(tmp_path,monkeypatch):
    out = tmp_path/'prepared'
    module.prepare(provider(tmp_path), out, timeout=2)
    frozen = module.load(out)
    def fail(*a):
        intent = json.loads((tmp_path/'capture'/'intent.json').read_text())
        assert intent['generator'] == frozen
        assert not list((tmp_path/'capture').glob('reservation-*.json'))
        raise LabError('fixture_preflight')
    monkeypatch.setattr(ticket_collection,'build_context',fail)
    monkeypatch.setattr(ticket_collection,'source_provenance',lambda *a: {'fixture':True})
    with pytest.raises(LabError,match='fixture_preflight'):
        ticket_collection.run(tmp_path,tmp_path/'source.py','public',tmp_path/'capture',generation=frozen)
    with pytest.raises(LabError,match='plan_mismatch'):
        ticket_collection.run(tmp_path,tmp_path/'source.py','include_private',tmp_path/'wrong',generation=frozen)
    assert not (tmp_path/'wrong').exists()


def generated_capture(path,frozen,root):
    intent,execution,report = capture(path,root_id=root)
    intent['generator'] = frozen
    execution['intent_sha'] = digest(intent)
    report['intent_sha'] = digest(intent)
    report['execution_sha'] = digest(execution)
    for name,value in [('intent',intent),('execution',execution),('report',report)]:
        (path/(name+'.json')).write_text(canonical(value))


def test_original_receipt_reaches_collection_and_cannot_be_reused(tmp_path):
    out = tmp_path/'prepared'
    module.prepare(provider(tmp_path),out,timeout=2)
    frozen = module.load(out)
    paths = []
    for i in range(2):
        path = tmp_path/f'capture-{i}'
        generated_capture(path,frozen,str(i+1)*32)
        _,audit = ticket_import.read_capture(path, SOURCE)
        assert audit['generator_evidence'] == frozen
        paths.append(str(path))
    for count in (1,2):
        inputs = tmp_path/f'inputs-{count}.json'
        inputs.write_text(json.dumps(paths[:count]))
        directory = tmp_path/f'collection-{count}'
        task_catalog.main(['--ticket-captures',str(inputs),'--ticket-source',str(tmp_path/'source.py'),'--output',str(directory)])
        data,_,_ = task_catalog.read_collection(directory)
        identity = generator_strata.collection_identity(directory)
        if count == 1:
            strata = generator_strata.load(data,directory,identity)
            assert set(strata['group_labels'].values()) == {'generator/requested/fixture-model'}
            assert strata['summary']['validated_plan_receipts'] == 1
        else:
            with pytest.raises(ForecastDataError,match='receipt_reused'):
                generator_strata.load(data,directory,identity)


def test_closed_planner_rejects_extra_fields_and_unrelated_context():
    value = deepcopy(PLAN)
    value['command'] = 'arbitrary'
    with pytest.raises(LabError):
        Plan.parse(value)
    with pytest.raises(LabError):
        prompt([], 'benign_task', {'task':'other'})


def test_checked_collection_receipt_retains_projection_proof_binding(tmp_path,monkeypatch):
    from research.flow_forecast import checked_ticket
    from test_flow_forecast_checked_ticket import fake_binding
    out = tmp_path/'prepared'
    module.prepare(provider(tmp_path),out,timeout=2)
    frozen = module.load(out)
    path = tmp_path/'capture'
    generated_capture(path,frozen,'1'*32)
    _, capture_audit = ticket_import.read_capture(path, SOURCE)
    monkeypatch.setattr(checked_ticket,'bind_capture',lambda *a:fake_binding(capture_audit))
    pairs = tmp_path/'pairs.json'
    pairs.write_text(json.dumps([{'capture':str(path),'interventions':'fixture'}]))
    directory = tmp_path/'checked'
    task_catalog.main(['--checked-ticket-captures',str(pairs),'--ticket-source',str(tmp_path/'source.py'),'--output',str(directory)])
    data,catalog,audit = task_catalog.read_collection(directory)
    identity = generator_strata.collection_identity(directory)
    assert generator_strata.load(data,directory,identity)['summary']['validated_plan_receipts'] == 1
    changed = deepcopy(audit)
    changed['ticket_captures'][0]['closed_ticket_projection_evidence']['creation'] = 'different claim'
    monkeypatch.setattr(generator_strata,'read_collection',lambda *a:(data,catalog,changed))
    with pytest.raises(ForecastDataError,match='branch_mismatch'):
        generator_strata.load(data,directory,identity)
