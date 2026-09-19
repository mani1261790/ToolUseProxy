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
GROUPING_METHOD = "declared-relations-and-flow-refinement-v2"


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



def _flow_signature(row):
    """Name-invariant directed edge-labelled refinement; collisions join conservatively.

    This is not a proof of graph isomorphism or semantic independence. All source,
    sink and intermediate identifiers are excluded; operation/tool names remain.
    Refinement only splits partitions, so at most the number of vertices rounds
    are needed, including for cyclic graphs.
    """
    flow = row['flow']
    nodes = {endpoint for source, _, target in flow for endpoint in (source, target)}
    incoming = {node: [] for node in nodes}
    outgoing = {node: [] for node in nodes}
    for source, operation, target in flow:
        outgoing[source].append((operation, target))
        incoming[target].append((operation, source))
    colors = {node: 0 for node in nodes}
    count = 1
    for _ in range(len(nodes)):
        signatures = {node: (colors[node],
                            tuple(sorted((operation, colors[target]) for operation, target in outgoing[node])),
                            tuple(sorted((operation, colors[source]) for operation, source in incoming[node])))
                      for node in nodes}
        ranks = {signature: index for index, signature in enumerate(sorted(set(signatures.values())))}
        colors = {node: ranks[signature] for node, signature in signatures.items()}
        if len(ranks) == count:
            break
        count = len(ranks)
    return digest([sorted(row['tools']), sorted(colors.values()),
                   sorted((colors[source], operation, colors[target]) for source, operation, target in flow)])

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
            signature = _flow_signature(row)
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


def collect(catalog, samples, *, seed='split-v1', cohort=None):
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
    planned = None
    if cohort is not None:
        from .cohort_plan import binding
        plan_rows = []
        for row in bindings:
            selected = binding(cohort, catalog, row['design_id'])
            stable_group = digest([cohort['plan_sha'], selected['declared_group']])
            plan_rows.append((row['root_case_id'], stable_group, selected['partition']))
        planned = (cohort['plan_sha'], tuple(sorted(plan_rows)))
    data = assemble(tuple(branches), seed=seed, related_roots=tuple(sorted(set(relations))),
                    provenance=provenances.pop(), planned=planned)
    return data, {'schema': 1, 'grouping_method': GROUPING_METHOD, 'catalog_sha': digest(catalog), 'source_dataset_shas': sources,
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


def read_collection(directory):
    """Verify a complete local collection without certifying its research claims."""
    if directory.is_symlink() or not directory.is_dir():
        raise ForecastDataError('invalid_collection_directory')
    if {p.name for p in directory.iterdir()} != {
            'dataset', 'task-catalog.json', 'collection-evidence.json', 'origins', 'collection.json'}:
        raise ForecastDataError('incomplete_collection')
    seal = _json(_read(directory / 'collection.json'))
    if (type(seal) is not dict or set(seal) != {
            'schema', 'dataset_digest', 'catalog_sha', 'evidence_sha', 'origin_shas'}
            or type(seal['schema']) is not int or seal['schema'] != 1):
        raise ForecastDataError('invalid_collection_seal')
    documents = {}
    for name, field in (('task-catalog.json', 'catalog_sha'), ('collection-evidence.json', 'evidence_sha')):
        raw = _read(directory / name)
        if hashlib.sha256(raw).hexdigest() != seal[field]:
            raise ForecastDataError('collection_document_mismatch')
        documents[name] = _json(raw)
    catalog, audit = documents['task-catalog.json'], documents['collection-evidence.json']
    if type(audit) is not dict:
        raise ForecastDataError('invalid_collection_evidence')
    origins = read_origins(catalog, directory / 'origins')
    if {p.name for p in (directory / 'origins').iterdir()} != {key + '.md' for key in origins}:
        raise ForecastDataError('unknown_collection_origin')
    data = read_dataset(directory / 'dataset')
    manifest = _json(_read(directory / 'dataset' / 'manifest.json'))
    if (manifest['dataset_digest'] != seal['dataset_digest'] or sorted(origins) != seal['origin_shas']
            or audit.get('catalog_sha') != digest(catalog) or audit.get('dataset_sha') != digest(asdict(data))
            or audit.get('split_sha') != data.split.digest
            or audit.get('independence_verified') is not False or audit.get('prior_nonuse_verified') is not False):
        raise ForecastDataError('collection_identity_mismatch')
    return data, catalog, audit


def collect_assigned_searches(directories):
    """Use the recorded pretrial assignment, never a caller's posthoc root mapping."""
    from hook_monitor.evaluation.flow_forecast.search_import import import_search
    from hook_monitor.evaluation.flow_lab.task_assignment import validate as validate_assignment
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    catalog, origins, samples, audits = None, None, [], []
    total_bytes, total_branches = 0, 0
    for directory in directories:
        data, audit = import_search(directory)
        assignment = audit.get('task_assignment')
        if assignment is None:
            raise ForecastDataError('search_has_no_pretrial_assignment')
        context = validate_assignment(assignment)
        if catalog is None:
            catalog = assignment['catalog']
            origins = {key: value.encode() for key, value in assignment['origins'].items()}
        elif catalog != assignment['catalog']:
            raise ForecastDataError('collection_catalog_changed')
        total_bytes += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        total_branches += len(data.branches)
        if total_bytes > MAX_ARTIFACT_BYTES or total_branches > MAX_BRANCHES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {prefix.root_case_id: assignment['design_id'] for prefix in data.prefixes}))
        audits.append({'run_id': audit['run']['run_id'], 'assignment_sha': context['assignment_sha'],
                       'binding_source': 'saved_pretrial_identity', 'import_evidence': audit})
    data, evidence = collect(catalog, tuple(samples))
    evidence['assigned_searches'] = audits
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_stateful_captures(directories):
    """Bind captured flows using the assignment sealed before proposal generation."""
    from .stateful_import import read_capture
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    catalog, origins, samples, audits = None, None, [], []
    total = 0
    for directory in directories:
        data, audit = read_capture(directory)
        generation = audit['execution']['generator_evidence']
        if generation is None:
            raise ForecastDataError('capture_has_no_pretrial_assignment')
        assignment = generation['assignment']
        if catalog is None:
            catalog = assignment['catalog']
            origins = {key: value.encode() for key, value in assignment['origins'].items()}
        elif catalog != assignment['catalog']:
            raise ForecastDataError('collection_catalog_changed')
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {prefix.root_case_id: assignment['design_id'] for prefix in data.prefixes}))
        audits.append(audit)
    data, evidence = collect(catalog, tuple(samples))
    evidence['stateful_captures'] = audits
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_task_worlds(directories, *, checked=False):
    from .task_world_import import catalog as world_catalog, read_capture
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    catalog, origins = world_catalog()
    samples, audits, total = [], [], 0
    for directory in directories:
        if checked:
            from .checked_task_world import read_checked_capture
            if type(directory) is not dict or set(directory) != {'capture', 'interventions'}:
                raise ForecastDataError('invalid_checked_world_input')
            if any(type(value) is not str or not value for value in directory.values()):
                raise ForecastDataError('invalid_checked_world_input')
            data, audit = read_checked_capture(Path(directory['capture']), Path(directory['interventions']))
        else:
            data, audit = read_capture(directory)
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {audit['intent']['root']: 'world-' + audit['intent']['world']}))
        audits.append(audit)
    data, evidence = collect(catalog, tuple(samples))
    evidence['task_world_captures'] = audits
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_agenda_captures(directories, *, checked=False):
    from .agenda_import import catalog as agenda_catalog, read_capture
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    catalog, origins = agenda_catalog()
    samples, audits, total = [], [], 0
    for directory in directories:
        if checked:
            from .checked_agenda import read_checked_capture
            if (type(directory) is not dict or set(directory) != {'capture', 'interventions'}
                    or any(type(value) is not str or not value for value in directory.values())):
                raise ForecastDataError('invalid_checked_agenda_input')
            data, audit = read_checked_capture(Path(directory['capture']), Path(directory['interventions']))
        else:
            data, audit = read_capture(directory)
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {audit['intent']['root']: 'agenda'}))
        audits.append(audit)
    data, evidence = collect(catalog, tuple(samples))
    evidence['agenda_captures'] = audits
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_ticket_captures(directories, source_path, *, checked=False):
    from .bfcl_ticket_import import catalog as ticket_catalog, read_capture
    from .bfcl_ticket_reference import source_text
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    source = source_text(source_path)
    catalog, origins = ticket_catalog()
    samples, audits, total = [], [], 0
    for directory in directories:
        if checked:
            from .checked_ticket import read_checked_capture
            if (type(directory) is not dict or set(directory) != {'capture','interventions'}
                    or any(type(v) is not str or not v for v in directory.values())):
                raise ForecastDataError('invalid_checked_ticket_input')
            data, audit = read_checked_capture(Path(directory['capture']), Path(directory['interventions']), source)
        else:
            data, audit = read_capture(directory, source)
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {audit['intent']['root']: 'bfcl-ticket'}))
        audits.append(audit)
    data, evidence = collect(catalog, tuple(samples))
    evidence['ticket_captures'] = audits
    evidence['development_used'] = True
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_message_captures(directories, source_path):
    from .bfcl_message_import import catalog as message_catalog, read_capture
    from .bfcl_message_reference import source_text
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    source = source_text(source_path)
    catalog, origins = message_catalog()
    samples, audits, total = [], [], 0
    for directory in directories:
        data, audit = read_capture(directory, source)
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        samples.append((data, {audit['intent']['root']: 'bfcl-message'}))
        audits.append(audit)
    data, evidence = collect(catalog, tuple(samples))
    evidence['message_captures'] = audits
    evidence['development_used'] = True
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def collect_mbpp_captures(directories, source_path, *, checked=False):
    from .mbpp_import import catalog as mbpp_catalog, read_capture
    from .mbpp_batch import selected
    if type(directories) is not tuple or not 1 <= len(directories) <= MAX_INPUTS:
        raise ForecastDataError('invalid_collection_inputs')
    catalog, origins = mbpp_catalog(selected(source_path))
    samples, audits, total = [], [], 0
    for directory in directories:
        if checked:
            from .checked_mbpp import read_checked_capture
            if (type(directory) is not dict or set(directory) != {'capture', 'interventions'}
                    or any(type(value) is not str or not value for value in directory.values())):
                raise ForecastDataError('invalid_checked_mbpp_input')
            data, audit = read_checked_capture(Path(directory['capture']), Path(directory['interventions']), source_path)
        else:
            data, audit = read_capture(directory, source_path)
        total += len(canonical(audit).encode()) + len(canonical(asdict(data)).encode())
        if total > MAX_ARTIFACT_BYTES:
            raise ForecastDataError('collection_size_limit')
        task = audit['intent']['origin']['candidate']['task_id']
        samples.append((data, {audit['intent']['root']: 'mbpp-' + str(task)}))
        audits.append(audit)
    assignments = [a['intent'].get('cohort_assignment') for a in audits]
    cohort = None
    if any(a is not None for a in assignments):
        if any(a is None for a in assignments) or len({a['plan']['plan_sha'] for a in assignments}) != 1:
            raise ForecastDataError('collection_cohort_plan_mismatch')
        cohort = assignments[0]['plan']
    data, evidence = collect(catalog, tuple(samples), cohort=cohort)
    if cohort is not None:
        planned = {a['intent']['root']: a['intent']['cohort_assignment']['partition'] for a in audits}
        for prefix in data.prefixes:
            if data.split.partition(prefix) != planned[prefix.root_case_id]:
                raise ForecastDataError('collection_cohort_partition_mismatch')
        evidence['cohort_plan_sha'] = assignments[0]['plan']['plan_sha']
    evidence['mbpp_captures'] = audits
    if len(canonical(evidence).encode()) > MAX_ARTIFACT_BYTES:
        raise ForecastDataError('collection_size_limit')
    return data, evidence, catalog, origins


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--ticket-source', type=Path, help='Pinned original TicketAPI source for --ticket-captures')
    parser.add_argument('--message-source', type=Path, help='Pinned original MessageAPI source for --message-captures')
    parser.add_argument('--mbpp-source', type=Path, help='Pinned original MBPP JSONL, only with --mbpp-captures')
    inputs_group = parser.add_mutually_exclusive_group(required=True)
    inputs_group.add_argument('--checked-mbpp-captures', type=Path, help='JSON list of MBPP capture/interventions pairs')
    inputs_group.add_argument('--checked-ticket-captures', type=Path, help='JSON list of Ticket capture/interventions pairs')
    inputs_group.add_argument('--ticket-captures', type=Path, help='JSON list of completed Ticket capture directories')
    inputs_group.add_argument('--message-captures', type=Path, help='JSON list of completed Message capture directories')
    inputs_group.add_argument('--mbpp-captures', type=Path, help='JSON list of completed pinned MBPP captures')
    inputs_group.add_argument('--checked-task-worlds', type=Path, help='JSON list of capture/interventions directory pairs')
    inputs_group.add_argument('--checked-agenda-captures', type=Path, help='JSON list of agenda capture/interventions pairs')
    inputs_group.add_argument('--agenda-captures', type=Path, help='JSON list of completed agenda captures with endpoint evidence')
    inputs_group.add_argument('--task-worlds', type=Path, help='JSON list of completed task world capture directories')
    inputs_group.add_argument('--stateful-captures', type=Path, help='JSON list of completed generated capture directories')
    inputs_group.add_argument('--assigned-searches', type=Path, help='JSON list of completed assigned search directories')
    inputs_group.add_argument('--inputs', type=Path,
                        help='JSON list of {directory, roots} bindings for synthetic datasets')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--origins', type=Path,
                        help='Synthetic design documents named by SHA-256 with .md suffix')
    args = parser.parse_args(argv)
    if args.mbpp_source and not (args.mbpp_captures or args.checked_mbpp_captures):
        parser.error('--mbpp-source requires MBPP captures')
    if args.ticket_source and not (args.ticket_captures or args.checked_ticket_captures):
        parser.error('--ticket-source requires --ticket-captures')
    if args.message_source and not args.message_captures:
        parser.error('--message-source requires --message-captures')
    if args.message_captures:
        if args.catalog or args.origins or args.message_source is None:
            parser.error('Message captures require --message-source and use their captured definitions')
        paths = _json(_read(args.message_captures))
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_INPUTS
                or any(type(path) is not str or not path for path in paths)):
            raise ForecastDataError('invalid_collection_inputs')
        data, audit, catalog, origins = collect_message_captures(tuple(Path(path) for path in paths), args.message_source)
    elif args.checked_ticket_captures:
        if args.catalog or args.origins or args.ticket_source is None:
            parser.error('checked Ticket captures require --ticket-source and captured definitions')
        pairs = _json(_read(args.checked_ticket_captures))
        if type(pairs) is not list:
            raise ForecastDataError('invalid_checked_ticket_input')
        data, audit, catalog, origins = collect_ticket_captures(tuple(pairs), args.ticket_source, checked=True)
    elif args.ticket_captures:
        if args.catalog or args.origins or args.ticket_source is None:
            parser.error('Ticket captures require --ticket-source and use their captured definitions')
        paths = _json(_read(args.ticket_captures))
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_INPUTS
                or any(type(path) is not str or not path for path in paths)):
            raise ForecastDataError('invalid_collection_inputs')
        data, audit, catalog, origins = collect_ticket_captures(tuple(Path(path) for path in paths), args.ticket_source)
    elif args.checked_mbpp_captures:
        if args.catalog or args.origins or args.mbpp_source is None:
            parser.error('checked MBPP captures require --mbpp-source and use their captured definitions')
        pairs = _json(_read(args.checked_mbpp_captures))
        if type(pairs) is not list:
            raise ForecastDataError('invalid_checked_mbpp_input')
        data, audit, catalog, origins = collect_mbpp_captures(tuple(pairs), args.mbpp_source, checked=True)
    elif args.mbpp_captures:
        if args.catalog or args.origins or args.mbpp_source is None:
            parser.error('MBPP captures require --mbpp-source and use their captured definitions')
        paths = _json(_read(args.mbpp_captures))
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_INPUTS
                or any(type(path) is not str or not path for path in paths)):
            raise ForecastDataError('invalid_collection_inputs')
        data, audit, catalog, origins = collect_mbpp_captures(tuple(Path(path) for path in paths), args.mbpp_source)
    elif args.checked_agenda_captures:
        if args.catalog or args.origins:
            parser.error('checked agenda captures use their captured definitions')
        pairs = _json(_read(args.checked_agenda_captures))
        if type(pairs) is not list:
            raise ForecastDataError('invalid_checked_agenda_input')
        data, audit, catalog, origins = collect_agenda_captures(tuple(pairs), checked=True)
    elif args.checked_task_worlds:
        if args.catalog or args.origins:
            parser.error('checked task worlds use their captured definitions')
        pairs = _json(_read(args.checked_task_worlds))
        if type(pairs) is not list:
            raise ForecastDataError('invalid_checked_world_input')
        data, audit, catalog, origins = collect_task_worlds(tuple(pairs), checked=True)
    elif args.assigned_searches or args.stateful_captures or args.task_worlds or args.agenda_captures:
        if args.catalog or args.origins:
            parser.error('assigned captures use their recorded catalogs and origins')
        paths = _json(_read(args.assigned_searches or args.stateful_captures or args.task_worlds or args.agenda_captures))
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_INPUTS
                or any(type(path) is not str or not path for path in paths)):
            raise ForecastDataError('invalid_collection_inputs')
        collector = (collect_assigned_searches if args.assigned_searches else
                     collect_stateful_captures if args.stateful_captures else
                     collect_agenda_captures if args.agenda_captures else collect_task_worlds)
        data, audit, catalog, origins = collector(tuple(Path(path) for path in paths))
    else:
        if args.catalog is None or args.origins is None:
            parser.error('manual inputs require --catalog and --origins')
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
    dataset_identity = write_dataset(data, args.output / 'dataset')
    _write_private(args.output / 'collection-evidence.json', (canonical(audit) + '\n').encode())
    _write_private(args.output / 'task-catalog.json', (canonical(catalog) + '\n').encode())
    (args.output / 'origins').mkdir(mode=0o700)
    for identity, raw in origins.items():
        _write_private(args.output / 'origins' / (identity + '.md'), raw)
    # Publish a completion seal only after all provenance artifacts exist.
    seal = {'schema': 1, 'dataset_digest': dataset_identity,
            'catalog_sha': hashlib.sha256(_read(args.output / 'task-catalog.json')).hexdigest(),
            'evidence_sha': hashlib.sha256(_read(args.output / 'collection-evidence.json')).hexdigest(),
            'origin_shas': sorted(origins)}
    _write_private(args.output / 'collection.json', (canonical(seal) + '\n').encode())


if __name__ == '__main__':
    main()
