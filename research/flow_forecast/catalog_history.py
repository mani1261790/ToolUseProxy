"""Reject known related task origins before opening a new evaluation collection.

Only catalog metadata is read: no dataset, trace evidence or target files. A clean
result means no match within supplied history, not independence or prior nonuse.
"""
import argparse
from copy import deepcopy
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import MAX_ARTIFACT_BYTES, _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .generator_strata import collection_identity
from .task_catalog import MAX_INPUTS, MAX_DESIGNS, design_groups


def catalog_metadata(directory):
    identity = collection_identity(directory)
    seal = _json(_read(directory / 'collection.json'))
    raw = _read(directory / 'task-catalog.json')
    if len(raw) > MAX_ARTIFACT_BYTES or hashlib.sha256(raw).hexdigest() != seal['catalog_sha']:
        raise ForecastDataError('history_catalog_changed')
    catalog = _json(raw)
    design_groups(catalog)
    if sorted({row['origin']['artifact_sha'] for row in catalog['designs']}) != seal['origin_shas']:
        raise ForecastDataError('history_origin_identity_mismatch')
    if collection_identity(directory) != identity:
        raise ForecastDataError('history_collection_changed')
    return catalog, identity


def audit(candidate, prior):
    if type(prior) is not tuple or not 1 <= len(prior) <= MAX_INPUTS:
        raise ForecastDataError('invalid_prior_collections')
    catalogs, identities, references = [], [], {}
    total = 0
    for index, directory in enumerate((candidate,) + prior):
        catalog, identity = catalog_metadata(directory)
        if index and identity in identities[1:]:
            raise ForecastDataError('duplicate_prior_collection')
        identities.append(identity)
        total += len(canonical(catalog).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('history_size_limit')
        renamed = {row['id']: f'c{index}-d{n}' for n, row in enumerate(catalog['designs'])}
        for row in catalog['designs']:
            item = deepcopy(row)
            item['id'] = renamed[row['id']]
            item['parents'] = [renamed[key] for key in row['parents']]
            references[item['id']] = {'collection': identity, 'design': row['id'], 'candidate': index == 0}
            catalogs.append(item)
        if len(catalogs) > MAX_DESIGNS:
            raise ForecastDataError('history_design_limit')
    groups = design_groups({'schema': 1, 'designs': catalogs})
    prior_by_group = {}
    for key, group in groups.items():
        if not references[key]['candidate']:
            prior_by_group.setdefault(group, []).append({k: v for k, v in references[key].items() if k != 'candidate'})
    overlap = []
    for key, group in groups.items():
        if references[key]['candidate'] and group in prior_by_group:
            overlap.append({'design': references[key]['design'], 'prior': sorted(prior_by_group[group],
                           key=lambda row: (row['collection'], row['design']))})
    # Recheck metadata only; a history change must invalidate the result.
    for directory, identity in zip((candidate,) + prior, identities):
        if catalog_metadata(directory)[1] != identity:
            raise ForecastDataError('history_collection_changed')
    result = {'schema': 1, 'candidate_collection': identities[0], 'prior_collections': sorted(identities[1:]),
              'overlap': sorted(overlap, key=lambda row: row['design']),
              'status': 'known_related_origins' if overlap else 'no_match_in_supplied_history',
              'scope': 'all_declared_catalog_designs_conservative',
              'independence_verified': False, 'prior_nonuse_verified': False, 'history_complete': False,
              'targets_read': False}
    return {**result, 'audit_sha': digest(result)}


def require_no_known_overlap(candidate, prior):
    result = audit(candidate, prior)
    if result['overlap']:
        raise ForecastDataError('holdout_known_related_origins')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--prior', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = audit(args.candidate, tuple(args.prior))
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(canonical(result) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
