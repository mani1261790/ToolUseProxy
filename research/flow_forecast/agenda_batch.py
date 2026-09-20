"""One finite offline batch of actual synthetic agenda API dispatches."""
import argparse
import hashlib
import inspect
import math
import json
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab import agenda_api
from hook_monitor.evaluation.flow_lab.agenda_api import INITIAL
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from .agenda_cases import cases
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_world_interventions import execute


def script(case):
    if case not in cases():
        raise LabError('unknown_agenda_case')
    return ("import json\n" + inspect.getsource(agenda_api) + "\n"
            f"service=AgendaAPI({case['principal']!r})\ncalls=json.loads({canonical(case['calls'])!r})\n"
            "initial=service.snapshot();steps=[]\n"
            "for call in calls:\n"
            "    before=service.snapshot()\n"
            "    output=service.call(call['name'],call['arguments'])\n"
            "    steps.append({'call':call,'output':output,'before':before,'after':service.snapshot()})\n"
            "print(json.dumps({'initial':initial,'steps':steps,'final':service.snapshot()},sort_keys=True,separators=(',',':')))\n")


def verify(case, raw):
    if case not in cases() or len(raw) > 65536:
        raise LabError('invalid_agenda_observation')
    try:
        observed = json.loads(raw)
        # The only successful mutation in these fixed cases is the first call
        # in add-get-public. Other calls must leave every owner's state intact.
        states = [INITIAL] + [case['final_state']] * len(case['calls'])
        expected = {'initial': INITIAL, 'final': case['final_state'], 'steps': [
            {'call': call, 'output': output, 'before': states[i], 'after': states[i + 1]}
            for i, (call, output) in enumerate(zip(case['calls'], case['outputs'], strict=True))]}
        if canonical(observed) != canonical(expected):
            raise ValueError
        return {'case': case['name'], 'observation_sha': hashlib.sha256(raw).hexdigest(),
                'input_sha': digest(case['calls']), 'final_state_sha': digest(observed['final']),
                'calls_observed': len(observed['steps']), 'oracle_matched': True}
    except (ValueError, TypeError, KeyError):
        raise LabError('agenda_oracle_mismatch') from None


def run(repository, output, *, seconds=180, clock=time.monotonic, suite='api'):
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_agenda_budget')
    if suite not in ('api', 'projection'):
        raise LabError('unknown_agenda_suite')
    selected, make_script, verify_observation = cases(), script, verify
    if suite == 'projection':
        from . import agenda_projection
        selected = agenda_projection.cases()
        make_script, verify_observation = agenda_projection.script, agenda_projection.verify
    planned = sum(len(case['calls']) for case in selected)
    if planned > 20:
        raise LabError('agenda_trial_limit')
    root = Path(__file__).resolve().parents[2]
    implementation = source_provenance(root)
    start = clock()
    output.mkdir(mode=0o700)
    intent = {'schema': 1, 'suite': suite, 'cases': selected, 'planned_trials': planned,
              'implementation_sha': digest(implementation),
              'limits': {'trials': 20, 'seconds': seconds, 'bytes': 1024 ** 3}}
    def save(name, value):
        _write_private(output / (name + '.json'), canonical(value).encode())
    def check():
        elapsed = clock() - start
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if not 0 <= elapsed < seconds or size >= intent['limits']['bytes']:
            raise LabError('agenda_batch_budget_exhausted')
        return elapsed, size
    save('implementation', implementation)
    save('intent', intent)
    try:
        check()
        context = build_context(repository)
        image = build_image(repository, context=context)
        check_isolation(image)
        execution = {'intent_sha': digest(intent), 'image': image, 'context_sha': hashlib.sha256(context).hexdigest()}
        save('execution', execution)
        charged, rows = 0, []
        for index, case in enumerate(selected, 1):
            check()
            source = make_script(case)
            for number, call in enumerate(case['calls'], 1):
                charged += 1
                if charged > 20:
                    raise LabError('agenda_trial_limit')
                save(f'reservation-{charged}', {'number': charged, 'case_sha': digest(case), 'call_number': number,
                                               'call_sha': digest(call), 'script_sha': hashlib.sha256(source.encode()).hexdigest()})
            name = 'tup-lab-' + uuid.uuid4().hex
            save(f'container-{index}', {'name': name, 'image': image})
            raw = execute(image, source, name=name)
            row = verify_observation(case, raw)
            _write_private(output / f'observation-{index}.json', raw)
            save(f'result-{index}', row)
            rows.append(row)
        elapsed, size = check()
        if source_provenance(root) != implementation:
            raise LabError('agenda_implementation_changed')
        report = {'schema': 1, 'status': 'completed', 'intent_sha': digest(intent),
                  'execution_sha': digest(execution), 'results': rows, 'trial_charges': charged,
                  'elapsed_seconds': elapsed, 'artifact_bytes_before_report': size,
                  'new_model_calls': 0, 'independent_new_tasks_accepted': 0,
                  'receiver_observed': False, 'native_hook_tested': False,
                  'scope': 'closed_stateful_api_development_not_F01_or_unseen_evaluation',
                  'suite': suite, 'semantic_truth_promoted': False}
        save('report', report)
        return report
    except BaseException:
        elapsed = clock() - start
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        save('failure', {'schema': 1, 'status': 'failed',
                         'trial_reservations': len(list(output.glob('reservation-*.json'))),
                         'elapsed_seconds': elapsed if math.isfinite(elapsed) and elapsed >= 0 else None,
                         'artifact_bytes_before_failure': size, 'new_model_calls': 0,
                         'scope': 'failed_batch_not_completed_trial_evidence'})
        raise



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seconds', default=180, type=int)
    parser.add_argument('--suite', choices=('api', 'projection'), default='api')
    args = parser.parse_args(argv)
    print(canonical(run(args.repository, args.output, seconds=args.seconds, suite=args.suite)))


if __name__ == '__main__':
    main()
