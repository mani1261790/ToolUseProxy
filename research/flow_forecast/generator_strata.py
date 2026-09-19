"""Bind descriptive generator strata to sealed collection evidence.

Requested aliases remain aliases. No local receipt is promoted to a provider-
verified model version, and related roots with different generators stay grouped.
"""
from collections import defaultdict
from dataclasses import asdict
import re

from hook_monitor.evaluation.flow_forecast.dataset import _json, _read
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_lab.agent import Proposal
from hook_monitor.evaluation.flow_lab.generation_evidence import validate
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .task_catalog import read_collection


UNKNOWN = 'generator/missing-evidence'
MIXED = 'generator/mixed-requested-models'
PREFIX = 'generator/requested/'


def collection_identity(directory):
    """Read only the identity seal; prepare must never open source/test evidence."""
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_generation_collection_directory')
    raw = _read(directory / 'collection.json')
    if len(raw) > 1024 * 1024:
        raise ForecastDataError('generation_collection_seal_limit')
    value = _json(raw)
    if (type(value) is not dict or set(value) != {
            'schema', 'dataset_digest', 'catalog_sha', 'evidence_sha', 'origin_shas'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['origin_shas']) is not list or len(value['origin_shas']) > 10000):
        raise ForecastDataError('invalid_generation_collection_seal')
    for item in [value[k] for k in ('dataset_digest', 'catalog_sha', 'evidence_sha')] + value['origin_shas']:
        if type(item) is not str or re.fullmatch('[a-f0-9]{64}', item) is None:
            raise ForecastDataError('invalid_generation_collection_seal')
    return digest(value)


def _identity(data):
    return digest([sorted(digest(asdict(branch)) for branch in data.branches),
                   data.split.digest, sorted(data.related_roots), data.provenance])


def load(dataset, directory, expected_identity, *, check_budget=lambda: None):
    check_budget()
    if collection_identity(directory) != expected_identity:
        raise ForecastDataError('generation_collection_changed')
    source, catalog, audit = read_collection(directory)
    if _identity(source) != _identity(dataset):
        raise ForecastDataError('generation_collection_dataset_mismatch')
    roots = {prefix.root_case_id for prefix in dataset.prefixes}
    models, seen_calls = {}, set()
    try:
        for item in audit.get('assigned_searches', []):
            check_budget()
            original = item['import_evidence']
            root = item['run_id']
            if root not in roots or root in models or original['run']['run_id'] != root:
                raise ForecastDataError('generation_root_mismatch')
            requested = original['generator']['requested_model']
            attempts = defaultdict(list)
            for row in original['records']:
                attempts[row['attempt_id']].append(row)
            expected_branches = {b.branch_id for b in dataset.branches if b.prefix.root_case_id == root}
            recorded_branches = [row['branch_id'] for row in original['records']]
            if (set(recorded_branches) != expected_branches
                    or len(recorded_branches) != len(set(recorded_branches))):
                raise ForecastDataError('generation_branch_mismatch')
            complete = bool(attempts)
            for rows in attempts.values():
                generation = rows[0].get('generation')
                if any(row.get('generation') != generation for row in rows):
                    raise ForecastDataError('generation_attempt_mismatch')
                if generation is None:
                    complete = False
                    continue
                proposal = Proposal.parse({'status': 'propose', 'actions': [row['action'] for row in rows]})
                validate(generation, proposal, requested)
                if generation['call_id'] in seen_calls:
                    raise ForecastDataError('generation_receipt_reused')
                seen_calls.add(generation['call_id'])
            models[root] = requested if complete else None
        for item in audit.get('stateful_captures', []):
            from .generated_stateful import validate as validate_generated
            from .stateful_collection import dataset_from_traces
            check_budget()
            execution, report = item['execution'], item['report']
            root = execution['root']
            if root not in roots or root in models or report['execution_sha'] != digest(execution):
                raise ForecastDataError('generation_root_mismatch')
            frozen = execution['generator_evidence']
            validate_generated(frozen)
            assignment = frozen['assignment']
            bindings = [row for row in audit['bindings'] if row['root_case_id'] == root]
            if (assignment['catalog'] != catalog or len(bindings) != 1
                    or bindings[0]['design_id'] != assignment['design_id']):
                raise ForecastDataError('generation_assignment_mismatch')
            if frozen['plan'] != execution['plan'] or report['prepared_generation_sha'] != frozen['prepared_sha']:
                raise ForecastDataError('generation_plan_mismatch')
            rebuilt = dataset_from_traces(execution, report['conditions'])
            expected = sorted(digest(asdict(b)) for b in dataset.branches if b.prefix.root_case_id == root)
            if (sorted(digest(asdict(b)) for b in rebuilt.branches) != expected
                    or item['dataset_sha'] != digest(asdict(rebuilt))):
                raise ForecastDataError('generation_branch_mismatch')
            call_id = frozen['generation']['call_id']
            if call_id in seen_calls:
                raise ForecastDataError('generation_receipt_reused')
            seen_calls.add(call_id)
            models[root] = frozen['model']
    except (KeyError, TypeError, ValueError, LabError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_generation_collection_evidence') from error
    if collection_identity(directory) != expected_identity:
        raise ForecastDataError('generation_collection_changed')
    grouped = defaultdict(set)
    by_prefix = {prefix.prefix_id: prefix.root_case_id for prefix in dataset.prefixes}
    for prefix_id, group, _ in dataset.split.assignments:
        grouped[group].add(models.get(by_prefix[prefix_id]))
    labels = {group: UNKNOWN if None in names else PREFIX + next(iter(names)) if len(names) == 1 else MIXED
              for group, names in grouped.items()}
    by_partition = {part: sorted({labels[group][len(PREFIX):] for _, group, selected in dataset.split.assignments
                                 if selected == part and labels[group].startswith(PREFIX)})
                    for part in ('train', 'calibration', 'test')}
    return {'group_labels': labels, 'summary': {
        'status': 'requested_model_aliases_only', 'evaluated': False,
        'resolved_model_versions_verified': False, 'collection_identity': expected_identity,
        'requested_models_by_partition': by_partition,
        'unseen_test_requested_aliases': sorted(set(by_partition['test']) - set(by_partition['train'])),
        'groups_with_missing_evidence': sum(label == UNKNOWN for label in labels.values()),
        'groups_with_mixed_requested_models': sum(label == MIXED for label in labels.values()),
        'validated_plan_receipts': len(seen_calls)}}
