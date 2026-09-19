"""Finite input/private-field interventions on pinned MBPP dispatch bodies.

The intervention changes only the declared compute input and synthetic private
source expression. Compute/public/full bodies come from the captured dispatcher.
It establishes finite observations, not universal noninterference.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import _json
from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.transport import CANARY
from .mbpp_batch import checked
from .mbpp_contract import inspect_reference
from .mbpp_transport import call_for, dispatch_script

TRANSPORT_SHA = '5b5b24fe2af2cf0196ab82d64af03f1be07afcb616ea649be92318b22815cbb2'
PRIVATE_ALTERNATE = 'SYNTHETIC_MBPP_PRIVATE_ALTERNATE'


def cases(row):
    candidate = checked(row)
    result = []
    for name, index, private in [('baseline', 0, CANARY), ('change-private', 0, PRIVATE_ALTERNATE),
                                 ('change-input', 1, CANARY)]:
        example = candidate['cases'][index]
        compute = call_for(row, 1, 'public')
        compute['arguments']['arguments'] = example['arguments']
        record = {'result': example['expected'], 'private': private}
        result.append({'name': name, 'task_id': row['task_id'], 'case_index': index, 'private': private,
                       'calls': [compute, call_for(row, 2, 'public'), call_for(row, 2, 'include_private')],
                       'outputs': [{'task_id': row['task_id'], 'computed': True}, {'result': example['expected']}, record],
                       'final_state': record})
    return deepcopy(result)


def _replace_once(source, old, new):
    if source.count(old) != 1:
        raise LabError('mbpp_projection_template_changed')
    return source.replace(old, new, 1)


def script(row, case):
    path = Path(__file__).with_name('mbpp_transport.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != TRANSPORT_SHA:
        raise LabError('mbpp_projection_source_changed')
    inspect_reference(row)
    if not any(canonical(case) == canonical(item) for item in cases(row)):
        raise LabError('unknown_mbpp_projection_case')
    parts = ['steps=[]\n']
    for index, (number, variant) in enumerate([(1, 'public'), (2, 'public'), (2, 'include_private')]):
        original_call = call_for(row, number, variant)
        source = dispatch_script(row, original_call, number, variant, '172.30.0.2', 'a' * 32)
        if number == 1:
            source = _replace_once(source, f'call=json.loads({canonical(original_call)!r})',
                                   f'call=json.loads({canonical(case["calls"][index])!r})')
            source = _replace_once(source, "Path('/opt/flow-lab/protected.txt').read_text().strip()", repr(case['private']))
        source = _replace_once(source,
            "print(json.dumps({'call':call,'before':before,'after':after,'output':output},sort_keys=True,separators=(',',':')))\n",
            "steps.append({'call':call,'before':before,'after':after,'output':output})\n")
        parts.append(source)
    parts.append("print(json.dumps({'initial':None,'steps':steps,'final':after},sort_keys=True,separators=(',',':')))\n")
    return ''.join(parts)


def expected(case):
    states = [None] + [case['final_state']] * 3
    return deepcopy({'initial': None, 'final': case['final_state'], 'steps': [
        {'call': call, 'before': states[index], 'after': states[index + 1], 'output': output}
        for index, (call, output) in enumerate(zip(case['calls'], case['outputs'], strict=True))]})


def verify(row, case, raw):
    if len(raw) > 65536 or not any(canonical(case) == canonical(item) for item in cases(row)):
        raise LabError('invalid_mbpp_projection_observation')
    try:
        observed = _json(raw)
        if canonical(observed) != canonical(expected(case)):
            raise ValueError
        return {'case': case['name'], 'task_id': row['task_id'], 'observation_sha': hashlib.sha256(raw).hexdigest(),
                'input_sha': digest({'calls': case['calls'], 'private': case['private']}),
                'final_state_sha': digest(observed['final']), 'calls_observed': 3, 'oracle_matched': True,
                'public_output_sha': digest(observed['steps'][1]['output']),
                'private_output_sha': digest(observed['steps'][2]['output'])}
    except (ValueError, TypeError, KeyError) as error:
        raise LabError('mbpp_projection_oracle_mismatch') from error
