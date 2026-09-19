"""Post-prediction strata from source-bound closed API dispatch observations.

The predictor still sees the original Prefix. API names and task families are
descriptive evidence, not independent-sample or unseen-population certificates.
"""
from dataclasses import asdict, replace

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from .generator_strata import collection_identity, _identity
from .task_catalog import read_collection, design_groups

UNKNOWN = 'task-api/missing-evidence'


def branch_key(branch):
    return digest(asdict(branch))


def load(dataset, directory, expected_identity, *, check_budget=lambda: None):
    check_budget()
    if collection_identity(directory) != expected_identity:
        raise ForecastDataError('api_task_collection_changed')
    source_data, catalog, audit = read_collection(directory)
    if _identity(source_data) != _identity(dataset):
        raise ForecastDataError('api_task_dataset_mismatch')
    labels, roots, identities, seen_roots = {}, set(), {}, set()
    try:
        from . import bfcl_message_import, bfcl_ticket_import, checked_message, checked_ticket
        families = [('message_captures', 'bfcl-message', bfcl_message_import, checked_message,
                     'closed_message_projection_evidence'),
                    ('ticket_captures', 'bfcl-ticket', bfcl_ticket_import, checked_ticket,
                     'closed_ticket_projection_evidence')]
        for section, family, importer, checker, proof_key in families:
            for item in audit.get(section, []):
                check_budget()
                root = item['intent']['root']
                if root in seen_roots or not any(b.prefix.root_case_id == root for b in dataset.branches):
                    raise ForecastDataError('api_task_root_mismatch')
                seen_roots.add(root)
                # Legacy collections may lack the original public source. They
                # remain readable, but do not acquire verified API strata.
                if 'source_text' not in item:
                    continue
                intent, report = item['intent'], item['report']
                root = intent['root']
                actual = [b for b in dataset.branches if b.prefix.root_case_id == root]
                if not actual or root in roots:
                    raise ForecastDataError('api_task_root_mismatch')
                if [b for b in audit['bindings'] if b['root_case_id'] == root] != [
                        {'root_case_id':root, 'design_id':family, 'declared_group':design_groups(catalog)[family]}]:
                    raise ForecastDataError('api_task_design_mismatch')
                expected_design = importer.catalog()[0]['designs'][0]
                if [d for d in catalog['designs'] if d['id'] == family] != [expected_design]:
                    raise ForecastDataError('api_task_design_mismatch')
                rebuilt = importer.dataset(intent, item['execution'], report, item['source_text'])
                proof = item.get(proof_key)
                if proof is not None:
                    if checker.contract(item, proof['binding'], item['source_text']) != proof:
                        raise ForecastDataError('api_task_contract_mismatch')
                normalized = []
                for branch in actual:
                    edges = []
                    for edge in branch.transfers:
                        if edge.relation in ('json_projection', 'closed_compute'):
                            if proof is None or edge.evidence_digest != digest(proof):
                                raise ForecastDataError('api_task_contract_mismatch')
                            edge = replace(edge, relation='selection', evidence='unknown', evidence_digest=None)
                        edges.append(edge)
                    normalized.append(replace(branch, transfers=tuple(edges)))
                if (sorted(branch_key(b) for b in normalized) != sorted(branch_key(b) for b in rebuilt.branches)
                        or item['dataset_sha'] != digest(asdict(source_data_for(actual, dataset)))):
                    raise ForecastDataError('api_task_branch_mismatch')
                dispatched = {c['mode']: sorted({s['call']['name'] for s in c['steps'] if s['dispatched']})
                              for c in report['conditions']}
                for branch in actual:
                    labels[branch_key(branch)] = ('task-api/' + family,) + tuple(
                        'tool-api/' + name for name in dispatched[branch.policy_mode])
                roots.add(root)
                identities[root] = {'task':family, 'tools':sorted(set().union(*map(set, dispatched.values())))}
    except (KeyError, TypeError, ValueError, LabError) as error:
        if isinstance(error, ForecastDataError):
            raise
        raise ForecastDataError('invalid_api_task_evidence') from error
    if collection_identity(directory) != expected_identity:
        raise ForecastDataError('api_task_collection_changed')
    by_partition = {}
    for part in ('train', 'calibration', 'test'):
        selected = {b.prefix.root_case_id for b in dataset.branches if dataset.split.partition(b.prefix) == part}
        values = [identities[root] for root in selected if root in identities]
        by_partition[part] = {'tasks':sorted({v['task'] for v in values}),
                              'tools':sorted({tool for v in values for tool in v['tools']}),
                              'roots_with_evidence':len(values), 'roots_without_evidence':len(selected - roots)}
    return {'branch_labels':labels, 'summary':{
        'scope':'observed_closed_api_ids_not_independence', 'collection_identity':expected_identity,
        'partitions':by_partition,
        'unseen_test_tasks':sorted(set(by_partition['test']['tasks']) - set(by_partition['train']['tasks'])),
        'unseen_test_tools':sorted(set(by_partition['test']['tools']) - set(by_partition['train']['tools'])),
        'independence_verified':False, 'predictor_input_changed':False}}


def source_data_for(branches, dataset):
    from hook_monitor.evaluation.flow_forecast.dataset import assemble
    # Capture digests precede catalog regrouping; compare their original split.
    return assemble(tuple(branches), provenance=dataset.provenance)
