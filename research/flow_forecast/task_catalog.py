"""Declared task origins and conservative grouping before freezing a collection.

Names, prose and random seeds are not independent-sample evidence. The catalog
records claims and joins known relatives; it cannot certify semantic independence.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from collections import deque
from dataclasses import asdict
import re
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import (
    MAX_ARTIFACT_BYTES, MAX_BRANCHES, _json, _read, assemble, read_dataset, write_dataset,
)
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest

MAX_DESIGNS = 10000
MAX_INPUTS = 1000


def _identifier(value):
    if type(value) is not str or re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', value) is None:
        raise ForecastDataError('invalid_task_design_id')


def _text(value):
    if type(value) is not str or not 1 <= len(value.strip()) <= 2000:
        raise ForecastDataError('invalid_task_design_description')


def _identifiers(values):
    if type(values) is not list or not 1 <= len(values) <= 100 or len(values) != len(set(values)):
        raise ForecastDataError('invalid_task_design_structure')
    for value in values:
        _identifier(value)


def design_groups(catalog):
    """Return canonical related components, never a count of verified independent tasks."""
    try:
        if (type(catalog) is not dict or set(catalog) != {'schema', 'designs'}
                or type(catalog['schema']) is not int or catalog['schema'] != 1
                or type(catalog['designs']) is not list or not 1 <= len(catalog['designs']) <= MAX_DESIGNS):
            raise ForecastDataError('invalid_task_catalog')
        parent, signatures, origins = {}, {}, {}
        records = {}
        for row in catalog['designs']:
            if type(row) is not dict or set(row) != {
                    'id', 'objective', 'origin', 'parents', 'tools', 'flow', 'success', 'receiver_check'}:
                raise ForecastDataError('invalid_task_design')
            key = row['id']
            _identifier(key)
            if key in records:
                raise ForecastDataError('duplicate_task_design')
            records[key] = row
            parent[key] = key
            for field in ('objective', 'success', 'receiver_check'):
                _text(row[field])
            origin = row['origin']
            if (type(origin) is not dict or set(origin) != {'kind', 'artifact_sha', 'rationale'}
                    or origin['kind'] not in {'new_design', 'derived'}
                    or type(origin['artifact_sha']) is not str
                    or re.fullmatch(r'[a-f0-9]{64}', origin['artifact_sha']) is None):
                raise ForecastDataError('invalid_task_origin')
            _text(origin['rationale'])
            _identifiers(row['tools'])
            if type(row['parents']) is not list or len(row['parents']) > 100:
                raise ForecastDataError('invalid_task_parents')
            for related in row['parents']:
                _identifier(related)
            if len(row['parents']) != len(set(row['parents'])) or (origin['kind'] == 'derived') != bool(row['parents']):
                raise ForecastDataError('invalid_task_parents')
            flow = row['flow']
            if type(flow) is not list or not 1 <= len(flow) <= 100:
                raise ForecastDataError('invalid_task_flow')
            for edge in flow:
                if type(edge) is not list or len(edge) != 3:
                    raise ForecastDataError('invalid_task_flow')
                for token in edge:
                    _identifier(token)
            if len({tuple(edge) for edge in flow}) != len(flow):
                raise ForecastDataError('duplicate_task_flow')

        def find(key):
            while parent[key] != key:
                parent[key] = parent[parent[key]]
                key = parent[key]
            return key

        def join(a, b):
            a, b = find(a), find(b)
            parent[max(a, b)] = min(a, b)

        for key, row in records.items():
            # Conservatively collapse equal mechanics even with different prose.
            signature = digest([sorted(row['tools']), sorted(row['flow'])])
            join(key, signatures.setdefault(signature, key))
            join(key, origins.setdefault(row['origin']['artifact_sha'], key))
            for related in row['parents']:
                if related == key or related not in records:
                    raise ForecastDataError('unknown_task_parent')
                join(key, related)
        # Parent links describe derivation, so circular origins are malformed.
        pending = {key: len(row['parents']) for key, row in records.items()}
        children = {key: [] for key in records}
        for key, row in records.items():
            for related in row['parents']:
                children[related].append(key)
        ready = deque(key for key, count in pending.items() if count == 0)
        visited = 0
        while ready:
            key = ready.popleft()
            visited += 1
            for child in children[key]:
                pending[child] -= 1
                if pending[child] == 0:
                    ready.append(child)
        if visited != len(records):
            raise ForecastDataError('cyclic_task_origins')
        return {key: find(key) for key in sorted(records)}
    except (TypeError, ValueError, KeyError, RecursionError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_task_catalog') from error


def collect(catalog, samples, *, seed='split-v1'):
    """Bind actual artifact roots to designs, then recompute a new grouped split.

    samples contains (Dataset, {root_case_id: design_id}). Existing frozen plans
    cannot be reused: the collected artifact gets a new dataset/split identity.
    """
    groups = design_groups(catalog)
    if type(samples) is not tuple or not 1 <= len(samples) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    branches, relations, roots, bindings, sources = [], [], set(), [], []
    representatives = {}
    provenances = set()
    total_bytes = 0
    for data, mapping in samples:
        total_bytes += len(canonical(asdict(data)).encode())
        if total_bytes > MAX_ARTIFACT_BYTES or len(branches) + len(data.branches) > MAX_BRANCHES:
            raise ForecastDataError('collection_size_limit')
        actual = {p.root_case_id for p in data.prefixes}
        if (type(mapping) is not dict or set(mapping) != actual
                or any(type(value) is not str or value not in groups for value in mapping.values())):
            raise ForecastDataError('collection_root_binding_mismatch')
        if roots & actual:
            raise ForecastDataError('duplicate_collection_root')
        roots.update(actual)
        provenances.add(data.provenance)
        sources.append(digest(asdict(data)))
        branches.extend(data.branches)
        relations.extend(data.related_roots)
        for root, design in sorted(mapping.items()):
            representative = representatives.setdefault(groups[design], root)
            if root != representative:
                relations.append(tuple(sorted((representative, root))))
            bindings.append({'root_case_id': root, 'design_id': design, 'declared_group': groups[design]})
    if len(provenances) != 1:
        raise ForecastDataError('collection_provenance_mismatch')
    data = assemble(tuple(branches), seed=seed, related_roots=tuple(sorted(set(relations))),
                    provenance=provenances.pop())
    return data, {'schema': 1, 'catalog_sha': digest(catalog), 'source_dataset_shas': sources,
                  'bindings': sorted(bindings, key=lambda row: row['root_case_id']),
                  'dataset_sha': digest(asdict(data)), 'split_sha': data.split.digest,
                  'declared_design_count': len({row['design_id'] for row in bindings}),
                  'grouped_root_count': len({row[1] for row in data.split.assignments}),
                  'independence_verified': False, 'prior_nonuse_verified': False,
                  'origin_artifacts_verified': False, 'scope': 'declared_origins_and_related_groups'}


def read_origins(catalog, directory):
    """Verify and retain the supplied design documents, not their independence."""
    design_groups(catalog)
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_origin_directory')
    result, total = {}, 0
    for identity in sorted({row['origin']['artifact_sha'] for row in catalog['designs']}):
        raw = _read(directory / (identity + '.md'))
        total += len(raw)
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('origin_documents_size_limit')
        if not raw or hashlib.sha256(raw).hexdigest() != identity:
            raise ForecastDataError('origin_document_digest_mismatch')
        result[identity] = raw
    return result


def _write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path,
                        help='JSON list of {directory, roots} bindings for synthetic datasets')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--origins', required=True, type=Path,
                        help='Synthetic design documents named by SHA-256 with .md suffix')
    args = parser.parse_args(argv)
    catalog = _json(_read(args.catalog))
    design_groups(catalog)  # Reject invalid design claims before reading trial artifacts.
    origins = read_origins(catalog, args.origins)
    inputs = _json(_read(args.inputs))
    if type(inputs) is not list or not 1 <= len(inputs) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    samples = []
    total_bytes, total_branches = 0, 0
    for entry in inputs:
        if (type(entry) is not dict or set(entry) != {'directory', 'roots'}
                or type(entry['directory']) is not str or not entry['directory']):
            raise ForecastDataError('invalid_collection_input')
        data = read_dataset(Path(entry['directory']))
        total_bytes += len(canonical(asdict(data)).encode())
        total_branches += len(data.branches)
        if total_bytes > MAX_ARTIFACT_BYTES or total_branches > MAX_BRANCHES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, entry['roots']))
    data, audit = collect(catalog, tuple(samples))
    audit['origin_artifacts_verified'] = True
    audit['origin_verification_scope'] = 'supplied_document_bytes_match_declared_sha256'
    args.output.mkdir(mode=0o700)
    write_dataset(data, args.output / 'dataset')
    _write_private(args.output / 'collection-evidence.json', (canonical(audit) + '\n').encode())
    _write_private(args.output / 'task-catalog.json', (canonical(catalog) + '\n').encode())
    (args.output / 'origins').mkdir(mode=0o700)
    for identity, raw in origins.items():
        _write_private(args.output / 'origins' / (identity + '.md'), raw)


if __name__ == '__main__':
    main()
