"""Narrow computation/projection evidence for the registered closed task-world v1 programs.

A generic semantic edge stays unknown. This path requires exact operation hashes,
observed bytes, the input-only contract and matching finite interventions. It
establishes coarse object dependency, not arbitrary field-level semantic truth.
"""
from dataclasses import asdict, replace
import hashlib

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from .intervention_evidence import bind_capture
from .task_world_import import read_capture
from .task_worlds import operation_script


def read_checked_capture(capture, interventions):
    data, audit = read_capture(capture)
    binding = bind_capture(capture, interventions)
    intent = audit['intent']
    if (binding['capture_root'] != intent['root'] or binding['capture_report_sha'] != digest(audit['report'])
            or binding['definition_sha'] != digest(intent['definition'])):
        raise ForecastDataError('checked_capture_changed')
    # Reconstruct each local operation, including the wrapper reading the single
    # JSON input and the optional immutable synthetic source. No caller code is
    # accepted; even an equivalent replacement is rejected by this v1 contract.
    for condition in audit['report']['conditions']:
        for row in condition['steps']:
            if row['number'] == 4:
                continue  # Its independent receiver evidence was already checked.
            expected = operation_script(intent['world'], row['number'], intent['variant'],
                                        '172.18.0.2', row['step_id'])
            if row['command_sha'] != hashlib.sha256(expected.encode()).hexdigest():
                raise ForecastDataError('checked_world_command_mismatch')
    proof = {'schema': 1, 'binding': binding, 'definition_sha': digest(intent['definition']),
             'scope': 'closed_world_v1_coarse_object_dependency',
             'computation': 'single_plain_json_input_no_ambient_reads_and_observed_input_interventions',
             'projection': 'exact_result_object_preserved_and_private_field_equals_immutable_synthetic_source',
             'independence_verified': False, 'general_semantic_truth': False}
    branches = []
    for branch in data.branches:
        edges = []
        for edge in branch.transfers:
            if edge.relation == 'semantic':
                if (edge.sequence_no, edge.source, edge.target) != (2, 'value-1', 'value-2'):
                    raise ForecastDataError('unexpected_computation_edge')
                edge = replace(edge, relation='closed_compute', evidence='checked_computation', evidence_digest=digest(proof))
            elif edge.relation == 'selection':
                if (intent['variant'] != 'include_private' or edge.sequence_no != 3
                        or edge.source not in ('value-2', 'protected-source') or edge.target != 'value-3'):
                    raise ForecastDataError('unexpected_projection_edge')
                edge = replace(edge, relation='json_projection', evidence='checked_json_projection', evidence_digest=digest(proof))
            edges.append(edge)
        branches.append(replace(branch, transfers=tuple(edges)))
    result = assemble(tuple(branches), related_roots=data.related_roots, provenance=data.provenance)
    return result, {**audit, 'unchecked_dataset_sha': audit['dataset_sha'],
                    'dataset_sha': digest(asdict(result)), 'closed_computation_evidence': proof}
