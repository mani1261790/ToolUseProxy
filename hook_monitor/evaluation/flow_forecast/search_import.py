"""Read historical closed synthetic searches without redispatch or invented paths.

Search actions were independent fresh guard invocations. Import each action at
its own empty prefix, group the entire original search together, retain missing
observations as censored and mark intermediate provenance unknown. This is not a
reconstruction of a stateful multi-action environment.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
import sqlite3
import time

from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.budget import Budget
from hook_monitor.evaluation.flow_lab.controller import TERMINAL, validate_state
from hook_monitor.evaluation.flow_lab.models import Observation, RunSpec
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.search_state import APPLICATION_ID as SEARCH_ID
from hook_monitor.evaluation.flow_lab.storage import APPLICATION_ID as TRIAL_ID
from .branches import Continuation, Transfer
from .dataset import _json, assemble, write_dataset
from .prefix import ForecastDataError, InformationObject as Obj, ObservedStep as Step, canonical, digest, freeze_prefix


def _open(directory, relative, identity):
    path = directory / relative
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ForecastDataError('invalid_synthetic_storage_path')
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=.25)
    try:
        conn.execute('PRAGMA query_only=ON')
        deadline = time.monotonic() + 2
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if (conn.execute('PRAGMA application_id').fetchone()[0] != identity
                or conn.execute('PRAGMA user_version').fetchone()[0] != 1):
            raise ForecastDataError('synthetic_storage_schema_mismatch')
        return conn
    except BaseException:
        conn.close()
        raise


def import_search(directory: Path):
    directory = directory.absolute()
    try:
        with closing(_open(directory, 'search.sqlite3', SEARCH_ID)) as conn:
            row = conn.execute('SELECT substr(value,1,1048577) FROM state WHERE id=1').fetchone()
            if row is None or len(row[0]) > 1048576:
                raise ForecastDataError('invalid_search_state')
            state = _json(row[0])
        validate_state(state, Budget(**state['identity']['budget']))
        spec = RunSpec(**state['identity']['spec'])
        if spec.mode not in {'adaptive_search', 'benign_task'} or state['status'] not in TERMINAL or state['phase'] != 'ready':
            raise ForecastDataError('unfinished_search_not_importable')
        observations = {}
        with closing(_open(directory, 'trials/trials.sqlite3', TRIAL_ID)) as conn:
            row = conn.execute('SELECT substr(spec,1,8193),digest,state FROM lab_run WHERE run_id=?',
                               (spec.run_id,)).fetchone()
            if (not row or len(row[0]) > 8192 or RunSpec(**_json(row[0])) != spec
                    or row[1] != spec.digest or row[2] not in {'complete', 'budget_exhausted'}):
                raise ForecastDataError('search_trial_revision_mismatch')
            if conn.execute('SELECT COUNT(*) FROM lab_pending WHERE run_id=?', (spec.run_id,)).fetchone()[0]:
                raise ForecastDataError('unresolved_search_dispatch')
            records = conn.execute(
                'SELECT attempt_id,step_id,tool_use_id,step_no,substr(payload,1,8193) '
                'FROM lab_observation WHERE run_id=? ORDER BY sequence_no LIMIT 201', (spec.run_id,),
            ).fetchall()
            if len(records) > 200:
                raise ForecastDataError('search_import_limit')
            for attempt, step, tool, number, encoded in records:
                if len(encoded) > 8192:
                    raise ForecastDataError('search_import_limit')
                observation = Observation(**_json(encoded))
                if ((observation.attempt_id, observation.step_id, observation.tool_use_id, observation.step_no)
                        != (attempt, step, tool, number) or observation.run_id != spec.run_id or step in observations):
                    raise ForecastDataError('search_observation_identity_mismatch')
                observations[step] = observation
        prefix = freeze_prefix(root_case_id=spec.run_id, observations=(), max_sequence_no=0,
                               objects=(Obj('private-source', 'source', 0), Obj('public-source', 'source', 0)),
                               capabilities=('http',), environment_version=spec.environment_digest,
                               source_version='synthetic-source-v1', protected_sources=('private-source',))
        branches, audit, consumed = [], [], set()
        for plan in state['plans']:
            actions = Proposal.parse({'status': 'propose', 'actions': plan['actions']}).actions
            for index, (step_id, action) in enumerate(zip(plan['steps'], actions), 1):
                observation = observations.get(step_id)
                if observation and (observation.attempt_id != plan['attempt'] or observation.step_no != index or observation.tool_use_id != step_id):
                    raise ForecastDataError('search_plan_identity_mismatch')
                consumed.add(step_id)
                steps, objects, edges, arrivals = (), (), (), ()
                source = 'public-source' if action.source == 'public' else 'private-source'
                complete, termination = False, 'unknown'
                if observation:
                    complete = observation.observer_state == 'complete'
                    if observation.process_started == 'yes':
                        if observation.receiver_arrival == 'yes':
                            objects = (Obj('receiver', 'sink', 1),)
                            arrivals = (('receiver', 1),)
                            # Actual receipt is known, but the old recorder did not
                            # independently record each byte transform or parent edge.
                            edges = (Transfer(source, 'receiver', 1, 'unknown', 'unknown', None),)
                            steps = (Step(1, 'http', 'send', (source,), ('receiver',), 'ok'),)
                        else:
                            steps = (Step(1, 'http', 'send', (source,), (), 'unknown'),)
                    if observation.termination == 'blocked' and observation.process_started == 'no':
                        termination = 'blocked'
                    elif (observation.termination == 'completed' and complete
                          and observation.process_started == 'yes'
                          and observation.receiver_arrival != 'unknown'):
                        termination = 'completed'
                branches.append(Continuation(prefix, step_id, observation.policy_mode if observation else 'enforce',
                                             'historical_observation', 'adaptive_search', None, steps, objects, edges,
                                             prefix.protected_sources, arrivals, complete, termination, spec.run_id))
                audit.append({'step_id': step_id, 'action': asdict(action),
                              'observation': asdict(observation) if observation else None})
        if set(observations) - consumed:
            raise ForecastDataError('unmapped_search_observation')
        return assemble(tuple(branches), provenance='synthetic-flow-lab-v1'), {
            'schema': 1, 'kind': 'historical_synthetic_search', 'run': asdict(spec),
            'records': audit, 'source_state_digest': digest(state),
            'limitations': ['no_paired_counterfactual', 'no_recorded_intermediate_truth',
                            'independent_fresh_guard_actions', 'not_natural_frequencies'],
        }
    except ForecastDataError:
        raise
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, LabError) as exc:
        raise ForecastDataError('invalid_synthetic_search') from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--search-directory', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        dataset, audit = import_search(args.search_directory)
        args.output_directory.mkdir(mode=0o700)
        identity = write_dataset(dataset, args.output_directory / 'dataset')
        (args.output_directory / 'import-evidence.json').write_text(canonical(audit) + '\n')
        print(canonical({'status': 'imported', 'dataset_digest': identity, 'summary': dataset.summary()}))
    except (ForecastDataError, OSError) as exc:
        print(canonical({'status': 'not_completed', 'reason': str(exc) if isinstance(exc, ForecastDataError) else 'import_io_error'}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
