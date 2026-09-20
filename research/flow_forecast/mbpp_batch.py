"""Nine reference calls from three pinned MBPP development tasks, in Docker.

Only these reviewed records can execute. No candidate inventory is a general
code execution allowlist. Each call gets a fresh offline, unprivileged container.
"""
import argparse
import hashlib
import math
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from .mbpp_candidates import COMMIT, SOURCE_SHA, inspect_task
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_world_interventions import execute

RECORDS = {
    602: 'da99ce1c7e293ec99062af8fe62d0752fab4cdebe9a1eb8cc8f977c9d69297c7',
    603: '796a6b33281e636e65fef77c1e9ba270b782c60a7874b63a9102788ac62f7041',
    604: '5fe759bd237edee78c0aae690bf680709540918cc668e500c68e6e41fa6f9771',
}


def checked(row):
    if type(row) is not dict or digest(row) not in RECORDS.values():
        raise LabError('unreviewed_mbpp_record')
    candidate = inspect_task(row)
    if (RECORDS.get(row['task_id']) != candidate['record_sha']
            or candidate['status'] != 'candidate' or len(candidate['cases']) != 3):
        raise LabError('invalid_mbpp_reference_cases')
    return candidate


def selected(path):
    raw = _read(path)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise LabError('mbpp_source_digest_mismatch')
    rows = [_json(line) for line in raw.splitlines()]
    chosen = [row for row in rows if row['task_id'] in RECORDS]
    if sorted(row['task_id'] for row in chosen) != sorted(RECORDS):
        raise LabError('missing_mbpp_reference_records')
    for row in chosen:
        checked(row)
    return sorted(chosen, key=lambda row: row['task_id'])


def script(row, index):
    candidate = checked(row)
    if type(index) is not int or not 0 <= index < 3:
        raise LabError('invalid_mbpp_case_index')
    case = candidate['cases'][index]
    return ('import json\n' + row['code'] + '\n'
            + f'arguments=json.loads({canonical(case["arguments"])!r})\n'
            + f'result={candidate["function"]}(*arguments)\n'
            + "print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))\n")


def verify(row, index, raw):
    candidate = checked(row)
    if type(index) is not int or not 0 <= index < 3 or len(raw) > 65536:
        raise LabError('invalid_mbpp_observation')
    observed = _json(raw)
    case = candidate['cases'][index]
    return {'task_id': row['task_id'], 'case_index': index, 'record_sha': digest(row),
            'observation_sha': hashlib.sha256(raw).hexdigest(), 'case_sha': digest(case),
            'oracle_matched': canonical(observed) == canonical(case['expected'])}


def run(repository, source_path, output, *, seconds=180, clock=time.monotonic):
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_mbpp_budget')
    rows = selected(source_path)
    root = Path(__file__).resolve().parents[2]
    implementation = source_provenance(root)
    start = clock()
    output.mkdir(mode=0o700)
    intent = {'schema': 1, 'source_commit': COMMIT, 'source_sha': SOURCE_SHA,
              'records': [checked(row) for row in rows], 'planned_trials': 9,
              'implementation_sha': digest(implementation),
              'limits': {'trials': 20, 'seconds': seconds, 'bytes': 1024 ** 3}}
    def save(name, value):
        _write_private(output / (name + '.json'), canonical(value).encode())
    def size():
        return sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
    def check():
        elapsed, used = clock() - start, size()
        if not 0 <= elapsed < seconds or used >= intent['limits']['bytes']:
            raise LabError('mbpp_batch_budget_exhausted')
        return elapsed, used
    save('implementation', implementation)
    save('intent', intent)
    charged, results = 0, []
    try:
        check()
        context = build_context(repository)
        image = build_image(repository, context=context)
        check_isolation(image)
        execution = {'intent_sha': digest(intent), 'image': image, 'context_sha': hashlib.sha256(context).hexdigest()}
        save('execution', execution)
        for row in rows:
            for index in range(3):
                check()
                source = script(row, index)
                charged += 1
                if charged > intent['limits']['trials']:
                    raise LabError('mbpp_trial_limit')
                save(f'reservation-{charged}', {'number': charged, 'task_id': row['task_id'], 'case_index': index,
                                               'record_sha': digest(row), 'script_sha': hashlib.sha256(source.encode()).hexdigest()})
                name = 'tup-lab-' + uuid.uuid4().hex
                save(f'container-{charged}', {'name': name, 'image': image})
                raw = execute(image, source, name=name)
                # Keep the actual reply even if parsing or the oracle rejects it.
                _write_private(output / f'observation-{charged}.json', raw)
                result = verify(row, index, raw)
                save(f'result-{charged}', result)
                results.append(result)
        elapsed, used = check()
        if source_provenance(root) != implementation:
            raise LabError('mbpp_implementation_changed')
        report = {'schema': 1, 'status': 'completed', 'intent_sha': digest(intent),
                  'execution_sha': digest(execution), 'results': results, 'trial_charges': charged,
                  'all_oracles_matched': all(row['oracle_matched'] for row in results),
                  'elapsed_seconds': elapsed, 'artifact_bytes_before_report': used,
                  'new_model_calls': 0, 'independent_new_tasks_accepted': 0,
                  'receiver_observed': False, 'native_hook_tested': False,
                  'scope': 'pinned_reference_development_not_flow_truth_or_unseen_evaluation'}
        save('report', report)
        return report
    except BaseException:
        elapsed = clock() - start
        save('failure', {'schema': 1, 'status': 'failed', 'trial_reservations': charged,
                         'elapsed_seconds': elapsed if math.isfinite(elapsed) and elapsed >= 0 else None,
                         'artifact_bytes_before_failure': size(), 'new_model_calls': 0})
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
