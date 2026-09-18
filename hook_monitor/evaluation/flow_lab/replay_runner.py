"""Reproduce, minimize and compare a closed synthetic plan across two checkouts."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3

from .agent import Proposal
from .compare import compare_replays
from .findings import failure_signatures
from .minimize import minimize
from .models import RecordError, canonical
from .preflight import LabError, build_context
from .replay import ReplayCampaign, decode_result
from .search_state import APPLICATION_ID
from .storage import StoreError


def source_revision(repository):
    return 'source-' + hashlib.sha256(build_context(repository)).hexdigest()


def search_actions(directory: Path, attempt: int):
    if type(attempt) is not int or attempt < 1:
        raise LabError('invalid_search_attempt')
    path = (directory / 'search.sqlite3').resolve()
    if path.name != 'search.sqlite3':
        raise LabError('invalid_search_storage')
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        if conn.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID:
            raise LabError('search_schema_mismatch')
        row = conn.execute('SELECT substr(value,1,1048577) FROM state WHERE id=1').fetchone()
        if row is None or len(row[0]) > 1048576:
            raise LabError('invalid_search_state')
        state = json.loads(row[0])
        if state['identity']['spec']['mode'] not in {'adaptive_search', 'benign_task'}:
            raise LabError('search_mode_required')
        return Proposal.parse({'status': 'propose', 'actions': state['plans'][attempt-1]['actions']}).actions
    except (KeyError, IndexError, TypeError, ValueError):
        raise LabError('invalid_search_attempt') from None
    finally:
        conn.close()


def run_workflow(before: Path, after: Path, directory: Path, actions, *, max_replays=5, seconds=600):
    if max_replays < 3:
        raise LabError('replay_workflow_requires_three_cases')
    Proposal.parse({'status': 'propose', 'actions': [asdict(a) for a in actions]})
    revisions = {str(path): source_revision(path) for path in (before, after)}
    identity = {'before': revisions[str(before)], 'after': revisions[str(after)],
                'actions': [asdict(a) for a in actions], 'version': 1}
    with ReplayCampaign(directory, max_replays=max_replays, seconds=seconds) as campaign:
        workflow = campaign.state.get('workflow')
        if workflow is None:
            if campaign.state['cases']:
                raise LabError('unrelated_replay_campaign')
            workflow = {'identity': identity}
            campaign.state['workflow'] = workflow
            campaign.journal.write(campaign.state)
        if workflow.get('identity') != identity:
            raise LabError('replay_workflow_mismatch')
        if 'report' in workflow:
            return workflow['report']
        cursor = 0

        def replay(repository, plan):
            nonlocal cursor
            if cursor < len(campaign.state['cases']):
                case = campaign.state['cases'][cursor]
                if (case['detector_revision'] != revisions[str(repository)]
                        or case['actions'] != [asdict(a) for a in plan]):
                    raise LabError('replay_workflow_mismatch')
                if case['status'] != 'completed':
                    raise LabError('replay_requires_reconciliation')
                result = decode_result(case['result'])
            else:
                # Detect a checkout edit between the initial identity and dispatch.
                if source_revision(repository) != revisions[str(repository)]:
                    raise LabError('replay_source_changed')
                result = campaign.run(repository, plan, expected_revision=revisions[str(repository)])
            cursor += 1
            return result

        original = replay(before, actions)
        failures = failure_signatures(original)
        selected = original
        reduction_status = 'no_failure_observed'
        target = failures[0] if failures else None
        if target:
            reduced = minimize(original, target, lambda plan: replay(before, plan),
                               max_replays=max_replays-2)
            reduction_status = reduced.status
            candidates = [r for r in reduced.attempts if r.actions == reduced.actions
                          and r.observable and target in failure_signatures(r)]
            if candidates:
                selected = candidates[-1]
        updated = replay(after, selected.actions)
        comparison = compare_replays(selected, updated)
        # An unreproduced original remains evidence, but cannot prove a later fix.
        if target and reduction_status in {'not_reproduced', 'cause_unverified'}:
            comparison = {**comparison, 'status': 'inconclusive', 'reason': reduction_status}
        report = {
            'schema': 1, 'status': 'comparison_completed', 'synthetic_only': True,
            'original_run': original.spec.run_id, 'before_run': selected.spec.run_id,
            'after_run': updated.spec.run_id, 'minimization': reduction_status,
            'comparison': comparison, 'case_count': len(campaign.results),
            'trial_count': campaign.store.trial_count(),
            'cause_evidence': [{'action': asdict(a), 'policy_trace': [list(row) for row in trace]}
                               for a, trace in zip(selected.actions, selected.cause_traces)],
            'regression_candidate': {
                'schema': 1, 'actions': [asdict(a) for a in selected.actions],
                'original_failure': asdict(target) if target else None,
                'expected': ['public_task_completed' if a.source == 'public' else 'protected_not_delivered'
                             for a in selected.actions],
                'status': 'candidate_not_promoted',
            },
            'limitations': ['closed_synthetic_http_actions', 'controller_delivery_not_native_hook',
                            'cause_fingerprint_not_universal_causality_proof'],
        }
        workflow['report'] = report
        campaign.journal.write(campaign.state)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--case', type=Path, help='JSON with a closed synthetic actions array')
    source.add_argument('--search-directory', type=Path)
    parser.add_argument('--attempt', type=int, default=1)
    parser.add_argument('--max-replays', type=int, default=5)
    parser.add_argument('--seconds', type=int, default=500)
    options = parser.parse_args(argv)
    try:
        if options.case:
            with options.case.open('rb') as file:
                raw = file.read(65537)
            if len(raw) > 65536:
                raise LabError('replay_case_too_large')
            actions = Proposal.parse({'status': 'propose', 'actions': json.loads(raw)['actions']}).actions
        else:
            actions = search_actions(options.search_directory, options.attempt)
        report = run_workflow(options.before, options.after, options.output_directory, actions,
                              max_replays=options.max_replays, seconds=options.seconds)
    except (LabError, RecordError, StoreError, OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, (LabError, RecordError, StoreError)) else 'replay_input_or_io_error'
        print(canonical({'status': 'not_completed', 'reason': reason}))
        return 1
    print(canonical(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
