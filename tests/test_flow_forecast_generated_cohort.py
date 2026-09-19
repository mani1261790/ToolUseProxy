import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest, ForecastDataError
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import generated_mbpp, cohort_plan, mbpp_import, mbpp_collection, task_catalog
from test_flow_forecast_generated_mbpp import provider, generated_capture
from test_flow_forecast_mbpp_import import reference as mbpp_reference

reference=mbpp_reference


def plan(reference, partition='train'):
    catalog,origins=mbpp_import.catalog([reference])
    return cohort_plan.prepare(catalog,origins,{'mbpp-602':partition})


def test_cohort_in_request_before_model_and_collector_intent(monkeypatch,tmp_path,reference):
    model=provider(tmp_path)
    original=model.propose
    out=tmp_path/'prepared'
    expected=plan(reference)
    def observe(*args,**kwargs):
        request=json.loads((out/'request.json').read_text())
        assert request['cohort_assignment']['plan']==expected
        return original(*args,**kwargs)
    monkeypatch.setattr(model,'propose',observe)
    generated_mbpp.prepare(reference,model,out,timeout=2,cohort=expected)
    frozen=generated_mbpp.load(out)
    assert frozen['schema']==2
    monkeypatch.setattr(mbpp_collection,'selected',lambda p:[reference])
    def stop(*a):
        intent=json.loads((tmp_path/'capture/intent.json').read_text())
        assert intent['cohort_assignment']==frozen['cohort_assignment']
        raise LabError('fixture_stop')
    monkeypatch.setattr(mbpp_collection,'build_context',stop)
    with pytest.raises(LabError,match='fixture_stop'):
        mbpp_collection.run(tmp_path,Path('source'),602,'public',tmp_path/'capture',generation=frozen)
    with pytest.raises(LabError,match='cohort_mismatch'):
        mbpp_collection.run(tmp_path,Path('source'),602,'public',tmp_path/'wrong',generation=frozen,cohort=plan(reference,'test'))
    assert not (tmp_path/'wrong').exists()


def test_original_generation_cohort_required_during_import(tmp_path,reference):
    out=tmp_path/'prepared'
    generated_mbpp.prepare(reference,provider(tmp_path),out,timeout=2,cohort=plan(reference))
    frozen=generated_mbpp.load(out)
    directory=tmp_path/'capture'
    generated_capture(directory,frozen,'1'*32)
    with pytest.raises(ForecastDataError):
        mbpp_import.read_capture(directory,Path('source'))
    intent=json.loads((directory/'intent.json').read_text())
    execution=json.loads((directory/'execution.json').read_text())
    report=json.loads((directory/'report.json').read_text())
    intent['cohort_assignment']=frozen['cohort_assignment']
    execution['intent_sha']=report['intent_sha']=digest(intent)
    report['execution_sha']=digest(execution)
    for name,value in [('intent',intent),('execution',execution),('report',report)]:
        (directory/(name+'.json')).write_text(canonical(value))
    data,_,_,_=task_catalog.collect_mbpp_captures((directory,),Path('source'))
    assert {data.split.partition(p) for p in data.prefixes}=={'train'}
