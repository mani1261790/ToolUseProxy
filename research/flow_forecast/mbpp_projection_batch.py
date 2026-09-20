"""One finite offline batch of pinned MBPP input/private-field interventions."""
import argparse
import hashlib
import math
from pathlib import Path
import time
import uuid

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError, build_context, build_image, check_isolation
from .mbpp_batch import selected as source_records, checked
from .mbpp_candidates import COMMIT, SOURCE_SHA
from . import mbpp_projection as projection
from .provenance import source_provenance
from .task_catalog import _write_private
from .task_world_interventions import execute


def run(repository, source_path, task_id, output, *, seconds=180, clock=time.monotonic):
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_mbpp_projection_budget')
    rows = [row for row in source_records(source_path) if type(task_id) is int and row['task_id'] == task_id]
    if len(rows) != 1:
        raise LabError('unknown_mbpp_projection_task')
    reference = rows[0]
    selected = projection.cases(reference)
    suite = 'mbpp-field-projection'
    planned = sum(len(case['calls']) for case in selected)
    if planned > 20:
        raise LabError('mbpp_projection_trial_limit')
    root = Path(__file__).resolve().parents[2]
    implementation = source_provenance(root)
    start = clock()
    output.mkdir(mode=0o700)
    intent = {'schema': 1, 'suite': suite, 'cases': selected, 'planned_trials': planned,
              'implementation_sha': digest(implementation),
              'origin': {'source_commit': COMMIT, 'source_sha': SOURCE_SHA, 'candidate': checked(reference)},
              'transport_sha': projection.TRANSPORT_SHA,
              'limits': {'trials': 20, 'seconds': seconds, 'bytes': 1024 ** 3}}
    def save(name, value):
        _write_private(output / (name + '.json'), canonical(value).encode())
    def check():
        elapsed = clock() - start
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if not 0 <= elapsed < seconds or size >= intent['limits']['bytes']:
            raise LabError('mbpp_projection_batch_budget_exhausted')
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
            source = projection.script(reference, case)
            for number, call in enumerate(case['calls'], 1):
                charged += 1
                if charged > 20:
                    raise LabError('mbpp_projection_trial_limit')
                save(f'reservation-{charged}', {'number': charged, 'case_sha': digest(case), 'call_number': number,
                                               'call_sha': digest(call), 'script_sha': hashlib.sha256(source.encode()).hexdigest()})
            name = 'tup-lab-' + uuid.uuid4().hex
            save(f'container-{index}', {'name': name, 'image': image})
            raw = execute(image, source, name=name)
            _write_private(output / f'observation-{index}.json', raw)
            row = projection.verify(reference, case, raw)
            save(f'result-{index}', row)
            rows.append(row)
        elapsed, size = check()
        if source_provenance(root) != implementation:
            raise LabError('mbpp_projection_implementation_changed')
        report = {'schema': 1, 'status': 'completed', 'intent_sha': digest(intent),
                  'execution_sha': digest(execution), 'results': rows, 'trial_charges': charged,
                  'elapsed_seconds': elapsed, 'artifact_bytes_before_report': size,
                  'new_model_calls': 0, 'independent_new_tasks_accepted': 0,
                  'receiver_observed': False, 'native_hook_tested': False,
                  'scope': 'pinned_mbpp_field_interventions_not_universal_truth',
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
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--task-id', required=True, type=int)
    args = parser.parse_args(argv)
    print(canonical(run(args.repository, args.source, args.task_id, args.output, seconds=args.seconds)))


if __name__ == '__main__':
    main()
