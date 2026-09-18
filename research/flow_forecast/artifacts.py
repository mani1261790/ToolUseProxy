"""Portable JSON model artifacts: fixed schema/digest, no pickle or executable state."""
from __future__ import annotations

import json
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .model import CONFIGURATION, SequenceModel
from .tokens import Action


MAX_MODEL_BYTES = 64 * 1024 * 1024


def save_model(model: SequenceModel, path: Path):
    if type(model) is not SequenceModel:
        raise ForecastDataError('invalid_sequence_model')
    value = {'model': model.payload(), 'sha256': model.model_digest}
    raw = (canonical(value) + '\n').encode()
    if len(raw) > MAX_MODEL_BYTES:
        raise ForecastDataError('model_storage_limit')
    with path.open('xb') as stream:
        stream.write(raw)
    return {'sha256': model.model_digest, 'bytes': len(raw), 'version': model.version}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ForecastDataError('duplicate_model_field')
        result[key] = value
    return result


def load_model(path: Path) -> SequenceModel:
    if path.is_symlink() or not path.is_file():
        raise ForecastDataError('invalid_model_file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_MODEL_BYTES + 1)
    if len(raw) > MAX_MODEL_BYTES:
        raise ForecastDataError('model_storage_limit')
    try:
        artifact = json.loads(raw, object_pairs_hook=_unique)
        if type(artifact) is not dict or set(artifact) != {'model', 'sha256'}:
            raise ForecastDataError('invalid_model_artifact')
        value = artifact['model']
        if (type(value) is not dict or set(value) != {'schema', 'algorithm', 'configuration', 'training_digest',
                                                     'training_roots', 'transitions'}
                or type(value['schema']) is not int or value['schema'] != 1
                or value['configuration'] != dict(CONFIGURATION)
                or type(value['training_roots']) is not list or type(value['transitions']) is not list):
            raise ForecastDataError('invalid_model_schema')
        if digest(value) != artifact['sha256']:
            raise ForecastDataError('model_digest_mismatch')
        transitions = {}
        for key, rows in value['transitions']:
            if key in transitions:
                raise ForecastDataError('duplicate_model_context')
            choices = []
            for action, probability in rows:
                if (type(action) is not dict or set(action) != {'tool', 'operation', 'result', 'inputs', 'outputs', 'links'}
                        or any(type(action[k]) is not list for k in ('inputs', 'outputs', 'links'))):
                    raise ForecastDataError('invalid_serialized_action')
                token = Action(action['tool'], action['operation'], action['result'],
                               tuple(tuple(ref) for ref in action['inputs']), tuple(action['outputs']),
                               tuple(tuple(link) for link in action['links']))
                choices.append((token, probability))
            transitions[key] = tuple(choices)
        model = SequenceModel(transitions, value['training_digest'], tuple(value['training_roots']), value['algorithm'])
        if model.model_digest != artifact['sha256']:
            raise ForecastDataError('noncanonical_model_artifact')
        return model
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, ForecastDataError):
            raise
        raise ForecastDataError('invalid_model_artifact') from None
