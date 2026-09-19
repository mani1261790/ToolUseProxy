import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.computation_contract import validate_program
from research.flow_forecast.task_worlds import WORLDS, definition


@pytest.mark.parametrize('name', WORLDS)
def test_closed_world_algorithms_only_read_declared_input(name):
    result = validate_program(definition(name)['program'])
    assert result['external_values'] == ['source']
    assert result['semantic_truth_promoted'] is False


@pytest.mark.parametrize('program', [
    "import os\nresult=os.environ",
    "result=open('protected.txt').read()",
    "result=Path('/protected').read_text()",
    "result=source.__class__",
    "result=getattr(source,'private')",
    "f=source.get\nresult=f('private')",
    "result=eval(source)",
    "result=globals()",
    "result=source['code']()",
    "open=1\nresult=open('x')",
    "result=secret\nsecret=source",
    "if source:\n    secret=source\nresult=secret",
    "for value in source:\n    secret=value\nresult=secret",
    "result=sum(secret for value in source)",
    "result=source\nsource={}",
    "result=source\nwhile True: pass",
    "def work(): return source\nresult=work()",
    "result={**source}",
    "result=dict(**source)",
    "result=source.get(*source)",
    "result=[x for x in source]",
    "result=source\nraise Exception()",
    "result=source\nassert True, source",
])
def test_ambient_access_and_unsupported_python_are_rejected(program):
    with pytest.raises(ForecastDataError):
        validate_program(program)


def test_definite_assignment_and_comprehension_scope():
    validate_program("if source:\n    result=1\nelse:\n    result=2")
    validate_program("result=all(any(left<=x for left in source) for x in source)")
    with pytest.raises(ForecastDataError):
        validate_program("result=all(x for x in source)\nresult=x")
