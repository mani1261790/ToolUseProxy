from copy import deepcopy

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from research.flow_forecast import cohort_plan, cohort_history, generated_mbpp, mbpp_import
from test_flow_forecast_cohort_plan import fixture
from test_flow_forecast_catalog_history import metadata
from test_flow_forecast_mbpp_import import reference as mbpp_reference

reference=mbpp_reference


def test_known_origins_only_allowed_in_training(tmp_path):
    cat,origins=fixture()
    old=metadata(tmp_path/'old',cat['designs'])
    value=cohort_plan.prepare(cat,origins,{'one':'train','two':'train'},prior=(old,))
    assert value['schema']==2
    assert cohort_history.known_designs(cat,value['history'])==['one','two']
    for partition in ('calibration','test'):
        with pytest.raises(ForecastDataError,match='known_origin_in_holdout'):
            cohort_plan.prepare(cat,origins,{'one':partition,'two':partition},prior=(old,))


def test_history_snapshot_tampering_and_duplicates_refused(tmp_path):
    cat,origins=fixture()
    old=metadata(tmp_path/'old',cat['designs'])
    value=cohort_plan.prepare(cat,origins,{'one':'train','two':'train'},prior=(old,))
    for change in ('text','identity','duplicate'):
        altered=deepcopy(value)
        if change=='text':
            altered['history'][0]['catalog_text']='{}'
        elif change=='identity':
            altered['history'][0]['collection_identity']='0'*64
        else:
            altered['history'].append(deepcopy(altered['history'][0]))
        altered['plan_sha']=digest({k:v for k,v in altered.items() if k!='plan_sha'})
        with pytest.raises(ForecastDataError):
            cohort_plan.validate(altered)


def test_changed_use_rejected_before_model_or_directory(tmp_path,reference):
    cat,origins=mbpp_import.catalog([reference])
    old=metadata(tmp_path/'old',cat['designs'])
    plan=cohort_plan.prepare(cat,origins,{'mbpp-602':'train'},prior=(old,))
    plan['assignments']['mbpp-602']='test'
    plan['plan_sha']=digest({k:v for k,v in plan.items() if k!='plan_sha'})
    class Never:
        def propose(self,*a,**k):
            pytest.fail('model invoked before history validation')
    with pytest.raises(ForecastDataError,match='known_origin_in_holdout'):
        generated_mbpp.prepare(reference,Never(),tmp_path/'output',cohort=plan)
    assert not (tmp_path/'output').exists()


def test_renamed_structure_cannot_avoid_history(tmp_path):
    cat,origins=fixture()
    old=metadata(tmp_path/'old',cat['designs'])
    cat['designs'][0]['id']='renamed'
    with pytest.raises(ForecastDataError,match='known_origin_in_holdout'):
        cohort_plan.prepare(cat,origins,{'renamed':'test','two':'test'},prior=(old,))


def test_new_holdout_generation_requires_supplied_history(tmp_path,reference):
    cat,origins=mbpp_import.catalog([reference])
    plan=cohort_plan.prepare(cat,origins,{'mbpp-602':'test'})
    with pytest.raises(ForecastDataError,match='history_required'):
        generated_mbpp.prepare(reference,object(),tmp_path/'output',cohort=plan)
    assert not (tmp_path/'output').exists()
