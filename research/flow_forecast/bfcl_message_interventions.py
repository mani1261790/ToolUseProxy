"""Finite MessageAPI field intervention observations in fresh offline containers.

Five cases, each charging one synthetic setup and three API invocations. No upstream
runner, dialogue data, host imports, model calls, or independent-group claims.
"""
import argparse
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_world_interventions import execute

COMMIT = '6ea57973c7a6097fd7c5915698c54c17c5b1b6c8'
SOURCE_SHA = 'cf72af1635654147af17df1891a7fb354549e78a61930139f741a31f4be21121'


def source_text(path):
    raw = _read(path)
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise LabError('message_source_digest_mismatch')
    return raw.decode('utf-8')


def cases():
    from .bfcl_message_reference import cases as reference_cases
    from hook_monitor.evaluation.flow_lab.transport import CANARY
    base = reference_cases()[0]['initial']
    base['inbox'][1]['USR003'] = CANARY
    rows = []
    for name in ('baseline', 'body', 'receiver', 'extra_entry', 'stored_counter'):
        initial = deepcopy(base)
        stats = {'received_count':3,'total_contacts':2}
        messages = {'USR002':['ARTIFICIAL duplicate','ARTIFICIAL duplicate'], 'USR003':[CANARY]}
        if name == 'body':
            initial['inbox'][1]['USR003'] = 'ARTIFICIAL_ALTERNATE_BODY'
            messages['USR003'] = ['ARTIFICIAL_ALTERNATE_BODY']
        elif name == 'receiver':
            initial['inbox'][1] = {'USR002':CANARY}
            stats = {'received_count':3,'total_contacts':1}
            messages = {'USR002':['ARTIFICIAL duplicate',CANARY,'ARTIFICIAL duplicate']}
        elif name == 'extra_entry':
            initial['inbox'].append({'USR001':'ARTIFICIAL extra'})
            stats = {'received_count':4,'total_contacts':3}
            messages['USR001'] = ['ARTIFICIAL extra']
        elif name == 'stored_counter':
            initial['message_count'] = 999
        final = deepcopy(initial)
        final['current_user'] = 'USR001'
        outputs = [{'login_status':True, 'message':"User 'USR001' logged in successfully."},
                   {'stats':stats}, {'messages':messages}]
        rows.append({'name':name, 'initial':initial, 'expected':{'outputs':outputs,'state':final}})
    return rows


def script(source, case):
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA or case not in cases():
        raise LabError('unreviewed_message_execution')
    return ('import json\n' + source + '\napi=MessageAPI()\n'
            + f'initial=json.loads({canonical(case["initial"])!r})\n'
            + 'initial["generated_ids"]=set(initial["generated_ids"])\napi._load_scenario(initial)\n'
            + 'outputs=[api.message_login(user_id="USR001"),api.get_message_stats(),api.view_messages_sent()]\n'
            + 'state={"generated_ids":sorted(api.generated_ids),"user_count":api.user_count,"user_map":api.user_map,'
              '"inbox":api.inbox,"message_count":api.message_count,"current_user":api.current_user}\n'
            + 'print(json.dumps({"outputs":outputs,"state":state},sort_keys=True,separators=(",",":"),allow_nan=False))\n')


def verify(case, raw):
    if case not in cases() or len(raw) > 65536:
        raise LabError('invalid_message_observation')
    observed = _json(raw)
    return dict(case_sha=digest(case), observation_sha=hashlib.sha256(raw).hexdigest(),
                oracle_matched=canonical(observed) == canonical(case['expected']))


def run(repository, source_path, output, *, seconds=180, clock=time.monotonic):
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_message_budget')
    source = source_text(source_path)
    selected = cases()
    root = Path(repository).resolve(strict=True)
    implementation = source_provenance(root)
    if implementation != source_provenance(Path(__file__).resolve().parents[2]):
        raise LabError('message_repository_implementation_mismatch')
    start = clock()
    output.mkdir(mode=0o700)
    intent = dict(schema=1, suite='message_field_interventions_v1', source_commit=COMMIT, source_sha=SOURCE_SHA, cases=selected,
                  implementation_sha=digest(implementation), planned_trials=20,
                  limits=dict(trials=20, seconds=seconds, bytes=1024**3))
    def save(name, value):
        _write_private(output / (name + '.json'), canonical(value).encode())
    def size():
        return sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
    def check():
        elapsed, used = clock() - start, size()
        if not 0 <= elapsed < seconds or used >= intent['limits']['bytes']:
            raise LabError('message_batch_budget_exhausted')
        return elapsed, used
    save('implementation', implementation)
    save('intent', intent)
    charged, results = 0, []
    try:
        check()
        context = build_context(root)
        image = build_image(root, context=context)
        check_isolation(image)
        execution = dict(intent_sha=digest(intent), image=image, context_sha=hashlib.sha256(context).hexdigest())
        save('execution', execution)
        for index, case in enumerate(selected, 1):
            check()
            program = script(source, case)
            if charged + 4 > intent['limits']['trials']:
                raise LabError('message_trial_limit')
            name = 'tup-lab-' + uuid.uuid4().hex
            save(f'reservation-{index}', dict(case_sha=digest(case), script_sha=hashlib.sha256(program.encode()).hexdigest(),
                 trial_charges=4, operations=['synthetic_state_setup', 'message_login', 'get_message_stats', 'view_messages_sent'], container=name, image=image))
            charged += 4
            raw = execute(image, program, name=name)
            _write_private(output / f'observation-{index}.json', raw)
            result = verify(case, raw)
            save(f'result-{index}', result)
            results.append(result)
        elapsed, used = check()
        if source_provenance(root) != implementation:
            raise LabError('message_implementation_changed')
        report = dict(schema=1, status='completed', intent_sha=digest(intent), execution_sha=digest(execution),
                      trial_charges=charged, api_calls=3 * len(results), results=results,
                      all_oracles_matched=all(row['oracle_matched'] for row in results),
                      elapsed_seconds=elapsed, artifact_bytes_before_report=used,
                      new_model_calls=0, accepted_independent_groups=0, receiver_observed=False,
                      scope='finite_message_interventions_not_universal_truth_or_unseen_evaluation')
        save('report', report)
        return report
    except BaseException:
        elapsed = clock() - start
        save('failure', dict(schema=1, status='failed', trial_reservations=charged,
             elapsed_seconds=elapsed if math.isfinite(elapsed) and elapsed >= 0 else None,
             artifact_bytes_before_failure=size(), new_model_calls=0))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args(argv)
    result = run(args.repository, args.source, args.output, seconds=args.seconds)
    print(canonical(result))
    return 0 if result['all_oracles_matched'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
