"""Finite input interventions; observations do not prove universal noninterference."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import (
    LabError, build_context, build_image, check_isolation, command, create_argv, document, validate_profile,
)
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_worlds import definition, encoded


def cases(name):
    world = definition(name)
    baseline = {'name': 'baseline', 'input': world['input'], 'answer': world['answer']}
    left, right = deepcopy(baseline), deepcopy(baseline)
    if name == 'inventory':
        left['name'] = 'increase-a-stock'
        left['input']['stock']['A'] = 7
        left['answer'] = {'accepted': ['o1', 'o2', 'o3'], 'remaining': {'A': 0, 'B': 1}}
        right['name'] = 'reverse-first-two-orders'
        right['input']['orders'][:2] = reversed(right['input']['orders'][:2])
        right['answer'] = {'accepted': ['o2', 'o3'], 'remaining': {'A': 1, 'B': 1}}
    elif name == 'calendar':
        left['name'] = 'shorten-duration'
        left['input']['duration'] = 20
        left['answer'] = {'start': 570, 'end': 590}
        right['name'] = 'remove-second-attendee-first-window'
        right['input']['availability'][1] = [[690, 750]]
        right['answer'] = {'start': 690, 'end': 720}
    else:
        left['name'] = 'increase-refund'
        left['input']['entries'][1]['cents'] = 300
        left['answer'] = {'balances': {'A': 900, 'B': 700}, 'total': 1600}
        right['name'] = 'unvoid-sale'
        right['input']['entries'][3]['kind'] = 'sale'
        right['answer'] = {'balances': {'A': 1500, 'B': 700}, 'total': 2200}
    return [baseline, left, right]


def script(name, case):
    # Only internally declared cases can be executed, never caller-supplied Python/data.
    if case not in cases(name):
        raise LabError('unknown_task_intervention')
    return ('import json,sys\n' + f'source=json.loads({encoded(case["input"]).decode()!r})\n'
            + definition(name)['program']
            + "sys.stdout.buffer.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode())\n")


def execute(image, source):
    name = 'tup-lab-' + uuid.uuid4().hex
    argv = create_argv(image, name)
    argv[-1] = source
    try:
        command(argv)
        info = document(['docker', 'inspect', name])
        if type(info) is not list or len(info) != 1:
            raise LabError('invalid_container_response')
        validate_profile(info[0], image)
        return command(['docker', 'start', '--attach', name], timeout=10)
    finally:
        # Remove exactly this invocation's randomly named container, including a
        # create that may have succeeded before the client observed a timeout.
        command(['docker', 'rm', '--force', name])


def run(repository, name, output, *, seconds=180, clock=time.monotonic):
    selected = cases(name)
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_intervention_budget')
    start = clock()
    implementation = source_provenance(Path(__file__).resolve().parents[2])
    output.mkdir(mode=0o700)
    intent = {'schema': 1, 'world': name, 'cases': selected, 'definition': definition(name),
              'limits': {'trials': 20, 'seconds': seconds, 'bytes': 1024 * 1024 * 1024},
              'planned_trials': len(selected), 'implementation_sha': digest(implementation)}
    _write_private(output / 'implementation.json', canonical(implementation).encode())
    _write_private(output / 'intent.json', canonical(intent).encode())
    def check():
        elapsed = clock() - start
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if not 0 <= elapsed < seconds or size >= intent['limits']['bytes']:
            raise LabError('intervention_budget_exhausted')
        return elapsed, size
    check()
    context = build_context(repository)
    image = build_image(repository, context=context)
    check_isolation(image)
    execution = {'intent_sha': digest(intent), 'image': image, 'context_sha': hashlib.sha256(context).hexdigest()}
    _write_private(output / 'execution.json', canonical(execution).encode())
    rows = []
    for number, case in enumerate(selected, 1):
        check()
        if number > intent['limits']['trials']:
            raise LabError('intervention_trial_budget_exhausted')
        source = script(name, case)
        _write_private(output / f'reservation-{number}.json', canonical({
            'number': number, 'case_sha': digest(case), 'script_sha': hashlib.sha256(source.encode()).hexdigest()}).encode())
        actual = execute(image, source)
        if len(actual) > 65536 or actual != encoded(case['answer']):
            raise LabError('intervention_answer_mismatch')
        row = {'case': case['name'], 'input_sha': digest(case['input']),
               'output_sha': hashlib.sha256(actual).hexdigest(), 'answer_matched': True,
               'changed_from_baseline': actual != encoded(selected[0]['answer'])}
        _write_private(output / f'result-{number}.json', canonical(row).encode())
        rows.append(row)
    elapsed, size = check()
    if source_provenance(Path(__file__).resolve().parents[2]) != implementation:
        raise LabError('intervention_implementation_changed')
    report = {'schema': 1, 'status': 'completed', 'intent_sha': digest(intent), 'execution_sha': digest(execution),
              'results': rows, 'trial_charges': len(rows), 'elapsed_seconds': elapsed,
              'artifact_bytes_before_report': size, 'new_model_calls': 0, 'independent_new_tasks_accepted': 0,
              'scope': 'finite_input_interventions_not_universal_information_flow_proof',
              'semantic_truth_promoted': False, 'native_hook_tested': False}
    _write_private(output / 'report.json', canonical(report).encode())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--world', required=True, choices=('inventory', 'calendar', 'ledger'))
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args(argv)
    try:
        result = run(args.repository, args.world, args.output, seconds=args.seconds)
    except LabError as error:
        print(json.dumps({'status': 'not_completed', 'reason': str(error)}))
        return 1
    print(canonical(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
