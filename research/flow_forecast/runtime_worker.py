"""Optional source-checkout worker for the packaged Hook's forecast transport.

No training, exploration, network, source-file reads, or implicit process start.
The structural adapter is experimental, not evidence of model effectiveness.
"""
from contextlib import closing
import json
from pathlib import Path
import time

from hook_monitor.evaluation.flow_forecast.prefix import InformationObject, ObservedStep, Prefix
from hook_monitor.runtime.forecast.journal import Journal
from hook_monitor.runtime.forecast.source import connect, digest, snapshot
from tooluseproxy.integrations.authority import registered_workspace_authority_lease
from .artifacts import load_model


def prefix_from_structure(structure):
    """Only explicit file operations with successful PostToolUse are supported.

    A registered lexical path is an observed structural hypothesis, not verified
    byte lineage. Unknown operations are rejected instead of inferred from text.
    The current candidate is bound separately, never recorded as already executed.
    """
    if structure['schema'] != 1 or len(structure['observations']) > 90:
        raise ValueError('runtime_structure_unsupported')
    objects = [InformationObject(key, 'source', 0) for key in structure['protected_paths']]
    current = {obj.object_id: obj.object_id for obj in objects}
    observations = []
    for index, row in enumerate(structure['observations'], 1):
        operation = row['operation']
        if operation not in {'read', 'copy'} or not row.get('source'):
            raise ValueError('runtime_operation_unsupported')
        source = row['source']
        if source not in current:
            objects.append(InformationObject(source, 'file', 0))
            current[source] = source
        output = digest(['runtime-output', index])
        if operation == 'copy':
            if not row.get('target'):
                raise ValueError('runtime_copy_target_missing')
            kind = 'file'
        else:
            kind = 'bytes'
        objects.append(InformationObject(output, kind, index))
        observations.append(ObservedStep(index, 'file', operation, (current[source],), (output,), 'ok'))
        if operation == 'copy':
            current[row['target']] = output
    return Prefix(digest([structure['workspace'], structure['session']]), len(observations),
                  tuple(observations), tuple(objects), ('file', 'http', 'shell', 'tool_output'),
                  'runtime-structure-v1', 'recorded-operations-v1',
                  protected_sources=tuple(structure['protected_paths']), task_kind='unknown')


def prediction(model, structure):
    try:
        prefix = prefix_from_structure(structure)
    except (ValueError, KeyError, TypeError):
        return {'status': 'unsupported', 'probability': None, 'model': model.model_digest}
    forecast = model.predict(prefix, policy_mode='enforce', horizon=4)
    probability = forecast.protected_probability
    known = forecast.unknown_probability == 0 and forecast.other_probability == 0 and probability is not None
    return {'status': 'predicted' if known else 'unknown', 'probability': probability if known else None,
            'model': model.model_digest}


def run_one(database, model, *, predict=prediction):
    database = Path(database)
    journal = Journal(database.parent / 'forecast.db')
    row = journal.claim(model.model_digest)
    if row is None:
        return 'idle'
    body = json.loads(row['body'])
    if digest(body) != row['id']:
        raise ValueError('runtime_request_digest_mismatch')
    structure, config = body['structure'], body['configuration']
    result = {'status': 'stale', 'probability': None, 'model': config['model']}
    try:
        with closing(connect(database, seconds=.5)) as conn:
            with registered_workspace_authority_lease(database, conn, structure['workspace']) as state:
                if state is not None and state.phase != 'active':
                    journal.finish(row['id'], result)
                    return 'stale'
                def current():
                    return (journal.configuration(structure['workspace']) == config
                            and config['model'] == model.model_digest
                            and snapshot(database, structure['workspace'], structure['session'], structure['event']) == structure)
                if current():
                    result = predict(model, structure)
                    if not current():
                        result = {'status': 'stale', 'probability': None, 'model': config['model']}
    except Exception:
        result = {'status': 'failed', 'probability': None, 'model': config['model']}
    journal.finish(row['id'], result)
    return result['status']


def serve(database, model_path, *, seconds):
    if type(seconds) not in (int, float) or not 0 < seconds <= 3600:
        raise ValueError('runtime_worker_duration_invalid')
    # Model is explicitly loaded once, outside the Hook. Its immutable content
    # digest must match the workspace configuration for each request.
    model = load_model(Path(model_path))
    deadline = time.monotonic() + seconds
    count = 0
    while time.monotonic() < deadline:
        status = run_one(database, model)
        if status == 'idle':
            time.sleep(.01)
        else:
            count += 1
    return {'processed': count, 'model': model.model_digest}
