"""Partition-separated artifacts: development reads never open test files.

Converting an existing Dataset does not establish prior non-use or independence.
The top-level seal contains identities only, never labels or dataset summaries.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import (
    Dataset, _json, _read, assemble, read_dataset, write_dataset,
)
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_forecast.splits import PARTITIONS
from .holdout import _sha


def _subset(dataset, partitions):
    branches = tuple(b for b in dataset.branches if dataset.split.partition(b.prefix) in partitions)
    roots = {b.prefix.root_case_id for b in branches}
    return assemble(branches, seed=dataset.split.seed, provenance=dataset.provenance,
                    related_roots=tuple(pair for pair in dataset.related_roots if set(pair) <= roots))


def write_bundle(dataset: Dataset, directory: Path):
    """Export already accessible data; never describe this conversion as unused."""
    parts = {name: _subset(dataset, {name}) for name in PARTITIONS}
    directory.mkdir(mode=0o700)
    seals = {}
    for name, part in parts.items():
        child = directory / name
        identity = write_dataset(part, child)
        seals[name] = {'dataset_sha': identity,
                       'manifest_sha': hashlib.sha256(_read(child / 'manifest.json')).hexdigest(),
                       'split_sha': part.split.digest}
    content = {'schema': 1, 'partitions': seals, 'seed': dataset.split.seed,
               'source_digest': digest(dataset.split.assignments),
               'prior_access': 'conversion_from_accessible_dataset'}
    manifest = {**content, 'bundle_sha': digest(content)}
    fd = os.open(directory / 'bundle.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(canonical(manifest) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    return manifest


def read_manifest(directory: Path):
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise ForecastDataError('invalid_bundle_directory')
        value = _json(_read(directory / 'bundle.json'))
        if (type(value) is not dict or set(value) != {
                'schema', 'partitions', 'seed', 'source_digest', 'prior_access', 'bundle_sha'}
                or type(value['schema']) is not int or value['schema'] != 1
                or value['prior_access'] != 'conversion_from_accessible_dataset'
                or type(value['partitions']) is not dict or set(value['partitions']) != set(PARTITIONS)
                or value['bundle_sha'] != digest({k: v for k, v in value.items() if k != 'bundle_sha'})):
            raise ForecastDataError('invalid_bundle_manifest')
        _sha(value['source_digest'])
        for seal in value['partitions'].values():
            if type(seal) is not dict or set(seal) != {'dataset_sha', 'manifest_sha', 'split_sha'}:
                raise ForecastDataError('invalid_partition_seal')
            for identity in seal.values():
                _sha(identity)
        return value
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        raise ForecastDataError('invalid_bundle_manifest') from error


def read_partition(directory, manifest, name):
    if name not in PARTITIONS:
        raise ForecastDataError('invalid_partition')
    child = directory / name
    if child.is_symlink():
        raise ForecastDataError('invalid_partition_directory')
    seal = manifest['partitions'][name]
    raw = _read(child / 'manifest.json')
    if hashlib.sha256(raw).hexdigest() != seal['manifest_sha']:
        raise ForecastDataError('partition_manifest_mismatch')
    data = read_dataset(child)
    if (_json(raw)['dataset_digest'] != seal['dataset_sha'] or data.split.digest != seal['split_sha']
            or data.split.seed != manifest['seed']
            or {row[2] for row in data.split.assignments} != {name}):
        raise ForecastDataError('partition_identity_mismatch')
    return data


def combine(parts):
    first = parts[0]
    if any((p.split.seed, p.provenance) != (first.split.seed, first.provenance) for p in parts):
        raise ForecastDataError('inconsistent_partition_metadata')
    result = assemble(tuple(b for p in parts for b in p.branches), seed=first.split.seed,
                      provenance=first.provenance,
                      related_roots=tuple(pair for p in parts for pair in p.related_roots))
    # Recompute across parts to detect equivalence groups that cross the boundary.
    expected = sorted(row for part in parts for row in part.split.assignments)
    if sorted(result.split.assignments) != expected:
        raise ForecastDataError('cross_partition_group')
    return result


def read_development(directory, manifest):
    return combine(tuple(read_partition(directory, manifest, name) for name in ('train', 'calibration')))
