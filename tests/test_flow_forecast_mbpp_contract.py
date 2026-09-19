import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast.mbpp_contract import inspect_program


@pytest.mark.parametrize('source', [
    'def size(values):\n    return len(values)\n',
    'def join_words(text):\n    return " ".join(reversed(text.split()))\n',
    'def enumerate_values(values):\n    result = []\n    for index, item in enumerate(values):\n        result.append(index + item)\n    return result\n',
])
def test_input_only_operations_are_descriptive_not_execution_permission(source):
    proof = inspect_program(source)
    assert proof['external_values'] == ['plain_json_arguments']
    assert proof['semantic_truth_promoted'] is False
    assert proof['execution_authorized'] is False
    assert proof['termination_proven'] is False


@pytest.mark.parametrize('source', [
    'import os\ndef f(x):\n    return x\n',
    'def f(x):\n    return Path("anything").read_text()\n',
    'def f(x):\n    return open("anything").read()\n',
    'def f(x):\n    return globals()\n',
    'def f(x):\n    return ambient\n',
    'def f(x):\n    return x.__class__\n',
    'def f(x):\n    callback = x.split\n    return callback()\n',
    'def f(x):\n    len = x\n    return len(x)\n',
    'def f(x):\n    return len\n',
    'def len(x):\n    return len(x)\n',
    '@decorator\ndef f(x):\n    return x\n',
    'def f(x=ambient):\n    return x\n',
    'def f(x: ambient):\n    return x\n',
    'def f(x):\n    def nested():\n        return x\n    return x\n',
    'def f(x):\n    global ambient\n    return x\n',
    'def f(x):\n    return [y for y in x]\n',
    'def f(x):\n    return len(*x)\n',
    'def f(x):\n    return x.split(sep=" ")\n',
])
def test_ambient_reads_reflection_aliases_and_unreviewed_syntax_rejected(source):
    with pytest.raises(ForecastDataError, match='unsupported_mbpp_computation'):
        inspect_program(source)


def test_inspection_does_not_run_even_nonterminating_source():
    source = 'def f(x):\n    while x:\n        x = x\n    return x\n'
    assert inspect_program(source)['termination_proven'] is False
