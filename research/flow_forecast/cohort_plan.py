"""Explicit catalog-level assignments, sealed before dispatch; no relabeling."""
import argparse
from copy import deepcopy
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import MAX_ARTIFACT_BYTES, _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from .task_catalog import design_groups, read_origins, _write_private

PARTITIONS = ('train', 'calibration', 'test')


def validate(value):
    try:
        if (type(value) is not dict or set(value) != {'schema', 'catalog', 'origins', 'assignments', 'plan_sha'}
                or type(value['schema']) is not int or value['schema'] != 1
                or len(canonical(value).encode()) > MAX_ARTIFACT_BYTES
                or value['plan_sha'] != digest({k:v for k,v in value.items() if k != 'plan_sha'})):
            raise ValueError
        groups = design_groups(value['catalog'])
        origins = value['origins']
        if type(origins) is not dict or set(origins) != {r['origin']['artifact_sha'] for r in value['catalog']['designs']}:
            raise ValueError
        for identity, document in origins.items():
            if type(document) is not str or not document or hashlib.sha256(document.encode()).hexdigest() != identity:
                raise ValueError
        assignments = value['assignments']
        if type(assignments) is not dict or set(assignments) != set(groups):
            raise ValueError
        selected = {}
        for design, partition in assignments.items():
            if type(partition) is not str or partition not in PARTITIONS:
                raise ValueError
            group = groups[design]
            if selected.setdefault(group, partition) != partition:
                raise ForecastDataError('cohort_related_partition_conflict')
        return groups
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_cohort_plan') from error


def prepare(catalog, origins, assignments):
    content = {'schema':1, 'catalog':deepcopy(catalog),
               'origins':{key:raw.decode('utf-8') for key,raw in origins.items()},
               'assignments':deepcopy(assignments)}
    result = {**content, 'plan_sha':digest(content)}
    validate(result)
    return result


def binding(plan, catalog, design):
    groups = validate(plan)
    if canonical(plan['catalog']) != canonical(catalog) or design not in groups:
        raise ForecastDataError('cohort_catalog_or_design_mismatch')
    return {'schema':1, 'plan':deepcopy(plan), 'design_id':design,
            'declared_group':groups[design], 'partition':plan['assignments'][design],
            'scope':'pretrial_intent_not_dataset_split_or_prior_nonuse_proof'}


def validate_binding(value, catalog, design):
    try:
        expected = binding(value['plan'], catalog, design)
        if canonical(value) != canonical(expected):
            raise ValueError
    except (TypeError, KeyError, ValueError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_cohort_binding') from error
    return value


def load(path):
    raw = _read(path)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('cohort_size_limit')
    value = _json(raw)
    validate(value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--origins', type=Path, required=True)
    parser.add_argument('--assignments', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    catalog = _json(_read(args.catalog))
    value = prepare(catalog, read_origins(catalog,args.origins), _json(_read(args.assignments)))
    _write_private(args.output, (canonical(value)+'\n').encode())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
