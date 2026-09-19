"""Pinned TicketAPI reference observations in fresh offline containers.

Six cases, each charging one synthetic setup and one API invocation. No upstream
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
SOURCE_SHA = '6a9375aa6425410c07a151aef27f3e44e9ed1023bb5cc5c25f14f4a9b3c99116'


def source_text(path):
    raw = _read(path)
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise LabError('ticket_source_digest_mismatch')
    return raw.decode('utf-8')


def cases():
    tickets = [dict(id=i, title=f'Artificial task {i}', description=f'Artificial description {i}',
                    status='Closed' if i == 3 else 'Open', priority=1,
                    created_by='B' if i == 2 else 'A') for i in (1, 2, 3)]
    initial = dict(ticket_queue=tickets, ticket_counter=4, current_user='A')
    rows = []
    def add(name, call, reply, after=None):
        rows.append(dict(name=name, call=call, initial=deepcopy(initial),
                         expected=dict(reply=deepcopy(reply), state=deepcopy(after or initial))))
    add('owner_open', 'api.get_user_tickets(status="open")', [tickets[0]])
    add('owner_closed', 'api.get_user_tickets(status="Closed")', [tickets[2]])
    add('lookup_other_owner', 'api.get_ticket(ticket_id=2)', tickets[1])
    after = deepcopy(initial)
    after['ticket_queue'][1].update(status='Resolved', resolution='Artificial resolution')
    add('resolve_other_owner', 'api.resolve_ticket(ticket_id=2, resolution="Artificial resolution")',
        {'status': 'Ticket 2 has been resolved successfully.'}, after)
    add('reject_unknown_field', 'api.edit_ticket(ticket_id=1, updates={"created_by":"B"})',
        {'error': 'Invalid fields for update: created_by'})
    after = deepcopy(initial)
    after['ticket_queue'][0]['priority'] = 0
    add('edit_priority_zero', 'api.edit_ticket(ticket_id=1, updates={"priority":0})',
        {'status': 'Ticket 1 has been updated successfully.'}, after)
    return rows


def script(source, case):
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA or case not in cases():
        raise LabError('unreviewed_ticket_execution')
    return ('import json\n' + source + '\napi=TicketAPI()\n'
            + f'api._load_scenario(json.loads({canonical(case["initial"])!r}))\n'
            + f'reply={case["call"]}\n'
            + 'state={"ticket_queue":api.ticket_queue,"ticket_counter":api.ticket_counter,"current_user":api.current_user}\n'
            + 'print(json.dumps({"reply":reply,"state":state},sort_keys=True,separators=(",",":"),allow_nan=False))\n')


def verify(case, raw):
    if case not in cases() or len(raw) > 65536:
        raise LabError('invalid_ticket_observation')
    observed = _json(raw)
    return dict(case_sha=digest(case), observation_sha=hashlib.sha256(raw).hexdigest(),
                oracle_matched=canonical(observed) == canonical(case['expected']))


def run(repository, source_path, output, *, seconds=180, clock=time.monotonic):
    if type(seconds) is not int or not 1 <= seconds <= 1800:
        raise LabError('invalid_ticket_budget')
    source = source_text(source_path)
    selected = cases()
    root = Path(__file__).resolve().parents[2]
    implementation = source_provenance(root)
    start = clock()
    output.mkdir(mode=0o700)
    intent = dict(schema=1, source_commit=COMMIT, source_sha=SOURCE_SHA, cases=selected,
                  implementation_sha=digest(implementation), planned_trials=12,
                  limits=dict(trials=20, seconds=seconds, bytes=1024**3))
    def save(name, value):
        _write_private(output / (name + '.json'), canonical(value).encode())
    def size():
        return sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
    def check():
        elapsed, used = clock() - start, size()
        if not 0 <= elapsed < seconds or used >= intent['limits']['bytes']:
            raise LabError('ticket_batch_budget_exhausted')
        return elapsed, used
    save('implementation', implementation)
    save('intent', intent)
    charged, results = 0, []
    try:
        check()
        context = build_context(repository)
        image = build_image(repository, context=context)
        check_isolation(image)
        execution = dict(intent_sha=digest(intent), image=image, context_sha=hashlib.sha256(context).hexdigest())
        save('execution', execution)
        for index, case in enumerate(selected, 1):
            check()
            program = script(source, case)
            if charged + 2 > intent['limits']['trials']:
                raise LabError('ticket_trial_limit')
            charged += 2
            name = 'tup-lab-' + uuid.uuid4().hex
            save(f'reservation-{index}', dict(case_sha=digest(case), script_sha=hashlib.sha256(program.encode()).hexdigest(),
                 trial_charges=2, operations=['synthetic_state_setup', 'ticket_api_call'], container=name, image=image))
            raw = execute(image, program, name=name)
            _write_private(output / f'observation-{index}.json', raw)
            result = verify(case, raw)
            save(f'result-{index}', result)
            results.append(result)
        elapsed, used = check()
        if source_provenance(root) != implementation:
            raise LabError('ticket_implementation_changed')
        report = dict(schema=1, status='completed', intent_sha=digest(intent), execution_sha=digest(execution),
                      trial_charges=charged, api_calls=len(results), results=results,
                      all_oracles_matched=all(row['oracle_matched'] for row in results),
                      elapsed_seconds=elapsed, artifact_bytes_before_report=used,
                      new_model_calls=0, accepted_independent_groups=0, receiver_observed=False,
                      scope='pinned_reference_development_not_flow_truth_or_unseen_evaluation')
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
