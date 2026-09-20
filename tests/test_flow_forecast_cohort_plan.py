from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest, canonical
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import cohort_plan as module, mbpp_collection, mbpp_import, task_catalog
from test_flow_forecast_task_catalog import design, catalog
from test_flow_forecast_mbpp_import import reference as mbpp_reference, capture

reference = mbpp_reference


def fixture():
    raw = b'Independent origin unverified.'
    row = design('one')
    row['origin']['artifact_sha'] = hashlib.sha256(raw).hexdigest()
    second = deepcopy(row)
    second['id'] = 'two'
    return catalog(row,second), {row['origin']['artifact_sha']:raw}


def test_relatives_cannot_receive_different_roles():
    cat, origins = fixture()
    with pytest.raises(ForecastDataError,match='related_partition_conflict'):
        module.prepare(cat,origins,{'one':'train','two':'test'})
    plan = module.prepare(cat,origins,{'one':'train','two':'train'})
    a = module.binding(plan,cat,'one')
    assert a['partition'] == 'train'
    a['plan']['assignments']['one'] = 'test'
    assert plan['assignments']['one'] == 'train'
    with pytest.raises(ForecastDataError):
        module.validate_binding(a,cat,'one')


def test_missing_design_origin_change_and_unknown_role_rejected():
    cat, origins = fixture()
    for roles in ({'one':'train'},{'one':'custom','two':'custom'}):
        with pytest.raises(ForecastDataError):
            module.prepare(cat,origins,roles)
    with pytest.raises(ForecastDataError):
        module.prepare(cat,{key:b'changed' for key in origins},{'one':'train','two':'train'})


def test_binding_fixed_before_any_trial(monkeypatch,tmp_path,reference):
    monkeypatch.setattr(mbpp_collection,'selected',lambda p:[reference])
    cat,origins=mbpp_import.catalog([reference])
    plan=module.prepare(cat,origins,{'mbpp-602':'train'})
    def fail(*a):
        intent=json.loads((tmp_path/'capture/intent.json').read_text())
        assert intent['cohort_assignment']['plan']['plan_sha'] == plan['plan_sha']
        assert not list((tmp_path/'capture').glob('reservation-*.json'))
        raise LabError('fixture_preflight')
    monkeypatch.setattr(mbpp_collection,'build_context',fail)
    with pytest.raises(LabError,match='fixture_preflight'):
        mbpp_collection.run(tmp_path,Path('source'),602,'public',tmp_path/'capture',cohort=plan)


def test_import_rejects_relabeling_even_with_rehashed_plan(tmp_path,reference):
    directory=tmp_path/'capture'
    intent,execution,report=capture(directory,reference)
    cat,origins=mbpp_import.catalog([reference])
    plan=module.prepare(cat,origins,{'mbpp-602':'train'})
    intent['cohort_assignment']=module.binding(plan,cat,'mbpp-602')
    intent['cohort_assignment']['partition']='test'
    execution['intent_sha']=report['intent_sha']=digest(intent)
    report['execution_sha']=digest(execution)
    for name,value in [('intent',intent),('execution',execution),('report',report)]:
        (directory/(name+'.json')).write_text(canonical(value))
    with pytest.raises(ForecastDataError,match='cohort_binding'):
        mbpp_import.read_capture(directory,Path('source'))


def test_collection_uses_predeclared_partition_instead_of_root_hash(tmp_path,reference):
    directory=tmp_path/'capture'
    intent,execution,report=capture(directory,reference)
    data,_=mbpp_import.read_capture(directory,Path('source'))
    selected=data.split.partition(data.prefixes[0])
    wrong='test' if selected != 'test' else 'train'
    cat,origins=mbpp_import.catalog([reference])
    intent['cohort_assignment']=module.binding(module.prepare(cat,origins,{'mbpp-602':wrong}),cat,'mbpp-602')
    execution['intent_sha']=report['intent_sha']=digest(intent)
    report['execution_sha']=digest(execution)
    for name,value in [('intent',intent),('execution',execution),('report',report)]:
        (directory/(name+'.json')).write_text(canonical(value))
    assigned,_audit,_catalog,_origins = task_catalog.collect_mbpp_captures((directory,),Path('source'))
    assert {assigned.split.partition(p) for p in assigned.prefixes} == {wrong}
