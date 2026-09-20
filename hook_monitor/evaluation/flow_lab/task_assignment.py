"""Bound a synthetic task catalog and its origin documents before model dispatch."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import os
import stat
from pathlib import Path

from .models import canonical
from .preflight import LabError
from .task_completion import validate as validate_completion

MAX_BYTES = 65536


def identity(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate(value):
    # This feature belongs to source-checkout research commands, not the installed Plugin.
    from research.flow_forecast.task_catalog import design_groups
    try:
        fields = {'schema', 'catalog', 'origins', 'design_id', 'assignment_sha'}
        if (type(value) is not dict or type(value.get('schema')) is not int
                or value['schema'] not in (1, 2)
                or set(value) != (fields if value['schema'] == 1 else fields | {'completion'})
                or len(canonical(value).encode()) + 1 > MAX_BYTES
                or value['assignment_sha'] != identity({k: v for k, v in value.items() if k != 'assignment_sha'})):
            raise ValueError
        if value['schema'] == 2:
            validate_completion(value['completion'])
        groups = design_groups(value['catalog'])
        if type(value['design_id']) is not str or value['design_id'] not in groups:
            raise ValueError
        origins = value['origins']
        required = {row['origin']['artifact_sha'] for row in value['catalog']['designs']}
        if type(origins) is not dict or set(origins) != required:
            raise ValueError
        for key, document in origins.items():
            if type(document) is not str or not document or hashlib.sha256(document.encode()).hexdigest() != key:
                raise ValueError
        selected = next(row for row in value['catalog']['designs'] if row['id'] == value['design_id'])
        if value['schema'] == 2 and 'http' not in selected['tools']:
            raise LabError('invalid_task_completion_contract')
        if not set(selected['tools']) <= {'http', 'file'}:
            raise LabError('unsupported_task_tools')
        return {'assignment_sha': value['assignment_sha'], 'catalog_sha': identity(value['catalog']),
                'design': deepcopy(selected), 'declared_group': groups[selected['id']],
                'scope': 'synthetic_composed_http_proposal_context', 'independence_verified': False,
                **({'completion': deepcopy(value['completion'])} if value['schema'] == 2 else {})}
    except LabError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise LabError('invalid_task_assignment') from error


def prepare(catalog, origins, design_id, *, completion=None):
    content = {'schema': 1, 'catalog': catalog,
               'origins': {key: raw.decode('utf-8') for key, raw in origins.items()}, 'design_id': design_id}
    if completion is not None:
        content.update(schema=2, completion=deepcopy(completion))
    value = {**content, 'assignment_sha': identity(content)}
    validate(value)
    return value


def load(path):
    from hook_monitor.evaluation.flow_forecast.dataset import _json
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise LabError('invalid_task_assignment_file')
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise LabError('task_assignment_size_limit')
    try:
        value = _json(raw)
    except (ValueError, TypeError, RecursionError) as error:
        raise LabError('invalid_task_assignment') from error
    validate(value)
    return value


def main(argv=None):
    from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
    from research.flow_forecast.task_catalog import read_origins
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--origins', type=Path, required=True)
    parser.add_argument('--design-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--completion-contract', type=Path)
    args = parser.parse_args(argv)
    catalog = _json(_read(args.catalog))
    value = prepare(catalog, read_origins(catalog, args.origins), args.design_id,
                    completion=_json(_read(args.completion_contract)) if args.completion_contract else None)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(canonical(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == '__main__':
    main()
