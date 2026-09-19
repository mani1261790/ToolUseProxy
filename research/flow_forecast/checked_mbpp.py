"""Coarse value dependencies for fixed successful MBPP wrapper executions.

Reference capability checks bound result inputs to public JSON arguments. The
reviewed wrapper stores private metadata separately and projects explicit fields.
This says nothing about field causality, timing, exceptions or independent tasks.
Finite interventions corroborate the contract; they do not prove it universally.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_lab.transport import CANARY
from .mbpp_import import read_capture
from .mbpp_projection import TRANSPORT_SHA
from .mbpp_contract import bind_capture as bind_computation
from .mbpp_projection_evidence import bind_capture


def contract(audit, binding, computation):
    intent, report = audit['intent'], audit['report']
    candidate = intent['origin']['candidate']
    if (binding['capture_root'] != intent['root'] or binding['capture_report_sha'] != digest(report)
            or binding['transport_source_sha'] != TRANSPORT_SHA
            or binding['record_sha'] != candidate['record_sha']
            or binding['semantic_truth_promoted'] is not False
            or computation['capture_root'] != intent['root']
            or computation['capture_report_sha'] != digest(report)
            or computation['capture_dataset_sha'] != audit['dataset_sha']
            or computation['reference_evidence']['candidate_sha'] != digest(candidate)):
        raise ForecastDataError('checked_mbpp_binding_changed')
    root = Path(__file__).resolve().parents[2]
    if hashlib.sha256((root / 'research/flow_forecast/mbpp_transport.py').read_bytes()).hexdigest() != TRANSPORT_SHA:
        raise ForecastDataError('checked_mbpp_source_changed')
    inspected = []
    for condition in report['conditions']:
        for row in condition['steps']:
            if not row['dispatched'] or row['number'] == 3:
                continue
            item = row['observation']['dispatch']
            before, after, output = item['before'], item['after'], item['output']
            if row['number'] == 1:
                arguments = row['call']['arguments']
                if (row['call']['name'] != 'mcp__mbpp__compute' or before is not None
                        or canonical(arguments) != canonical({'task_id': candidate['task_id'],
                                                              'arguments': candidate['cases'][0]['arguments']})
                        or canonical(after) != canonical({'result': candidate['cases'][0]['expected'], 'private': CANARY})
                        or canonical(output) != canonical({'task_id': candidate['task_id'], 'computed': True})):
                    raise ForecastDataError('checked_mbpp_compute_domain_mismatch')
            else:
                fields = ('result',) if intent['variant'] == 'public' else ('result', 'private')
                selected = {key: before[key] for key in fields}
                if (canonical(before) != canonical(after) or canonical(output) != canonical(selected)
                        or set(before) != {'result', 'private'} or before['private'] != CANARY):
                    raise ForecastDataError('checked_mbpp_query_domain_mismatch')
            inspected.append({'step_id': row['step_id'], 'number': row['number'],
                              'call_sha': row['call_sha'], 'observation_sha': digest(row['observation'])})
    return {'schema': 1, 'binding': binding, 'computation': computation,
            'transport_source_sha': TRANSPORT_SHA, 'operations': inspected,
            'scope': 'closed_mbpp_plain_json_coarse_value_dependency',
            'creation': 'reference reads only public arguments; wrapper stores private separately; acknowledgment copies public task id',
            'query': 'public projects result; full query additionally copies private',
            'assumptions': ['trusted Python standard library and Docker controller',
                            'fixed successful calls and plain JSON states validated by capture reader'],
            'general_semantic_truth': False, 'independence_verified': False,
            'timing_and_exception_flows_evaluated': False}


def read_checked_capture(capture, interventions, source_path):
    data, audit = read_capture(capture, source_path)
    proof = contract(audit, bind_capture(capture, interventions, source_path), bind_computation(capture, source_path))
    branches = []
    private = audit['intent']['variant'] == 'include_private'
    for branch in data.branches:
        if branch.prefix.source_version != 'pinned-mbpp-io-v1':
            raise ForecastDataError('checked_mbpp_visibility_version_mismatch')
        end = branch.prefix.max_sequence_no + len(branch.observations)
        required = {(1,'mbpp-input','mbpp-ack'), (2,'mbpp-input','mbpp-response')}
        if private:
            required.add((2,'protected-source','mbpp-response'))
        required = {item for item in required if item[0] <= end}
        actual = [(e.sequence_no,e.source,e.target) for e in branch.transfers if e.relation == 'selection']
        sends = [(e.sequence_no,e.source,e.target) for e in branch.transfers if e.relation == 'send']
        if (set(actual) != required or len(actual) != len(required)
                or sends != ([(3,'mbpp-response','receiver')] if end == 3 else [])):
            raise ForecastDataError('checked_mbpp_projection_coverage_mismatch')
        edges = []
        for edge in branch.transfers:
            if edge.relation == 'selection':
                allowed = {(1,'mbpp-input','mbpp-ack'), (2,'mbpp-input','mbpp-response')}
                if private:
                    allowed.add((2,'protected-source','mbpp-response'))
                if (edge.sequence_no,edge.source,edge.target) not in allowed:
                    raise ForecastDataError('checked_mbpp_unexpected_projection')
                edge = replace(edge, relation='json_projection', evidence='checked_json_projection', evidence_digest=digest(proof))
            elif edge.relation != 'send':
                raise ForecastDataError('checked_mbpp_unexpected_relation')
            edges.append(edge)
        branches.append(replace(branch, transfers=tuple(edges)))
    result = assemble(tuple(branches), related_roots=data.related_roots, provenance=data.provenance)
    return result, {**audit, 'unchecked_dataset_sha':audit['dataset_sha'],
                    'dataset_sha':digest(asdict(result)), 'closed_mbpp_projection_evidence':proof}
