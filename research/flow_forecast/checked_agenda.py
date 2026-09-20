"""Value-flow contract for one pinned, closed agenda program and capture domain.

The source pins identify reviewed code, not a proof by hash. On the accepted
plain-JSON path: add stores public fields and copies A.shared.private; its return
contains only id/created. Public query whitelists title/time; get copies the owned
record. Captured branch preconditions and field equalities are checked below.
Finite interventions support that contract but are not universal noninterference.
Timing, exceptions, other APIs/domains and an untrusted controller are out of scope.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import assemble
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from hook_monitor.evaluation.flow_lab.transport import CANARY
from .agenda_import import read_capture
from .agenda_projection import API_SHA
from .agenda_projection_evidence import bind_capture


TRANSPORT_SHA = 'c2a7006aa723786449ac8ad56e8b36762949776a820ca739de2757f6e40cc7af'


def contract(audit, binding):
    intent, report = audit['intent'], audit['report']
    if (binding['capture_root'] != intent['root'] or binding['capture_report_sha'] != digest(report)
            or binding['api_source_sha'] != API_SHA or binding['semantic_truth_promoted'] is not False):
        raise ForecastDataError('checked_agenda_binding_changed')
    root = Path(__file__).resolve().parents[2]
    for path, expected in [('hook_monitor/evaluation/flow_lab/agenda_api.py', API_SHA),
                           ('research/flow_forecast/agenda_transport.py', TRANSPORT_SHA)]:
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
            raise ForecastDataError('checked_agenda_source_changed')
    inspected = []
    for condition in report['conditions']:
        for row in condition['steps']:
            if not row['dispatched'] or row['number'] == 3:
                continue
            item = row['observation']['dispatch']
            before, after, output = item['before'], item['after'], item['output']
            if row['number'] == 1:
                arguments = row['call']['arguments']
                # A valid fixed add: no existing key, one inserted plain record,
                # unchanged B and existing A record, and an acknowledgment only.
                if (row['call']['name'] != 'mcp__agenda__add' or arguments['id'] != 'new'
                        or set(before['A']) != {'shared'} or set(after['A']) != {'shared', 'new'}
                        or before['A']['shared'] != after['A']['shared'] or before['B'] != after['B']
                        or before['A']['shared']['private'] != CANARY
                        or after['A']['new'] != {'title':arguments['title'], 'time':arguments['time'], 'private':CANARY}
                        or output != {'id':arguments['id'], 'created':True}):
                    raise ForecastDataError('checked_agenda_add_domain_mismatch')
            else:
                fields = ('title', 'time') if intent['variant'] == 'public' else ('title', 'time', 'private')
                selected = {'id':'new', **{key:before['A']['new'][key] for key in fields}}
                if (before != after or canonical(output) != canonical(selected)
                        or before['A']['new']['private'] != CANARY):
                    raise ForecastDataError('checked_agenda_query_domain_mismatch')
            inspected.append({'step_id':row['step_id'], 'number':row['number'],
                              'call_sha':row['call_sha'], 'observation_sha':digest(row['observation'])})
    return {'schema':1, 'binding':binding, 'api_source_sha':API_SHA, 'transport_source_sha':TRANSPORT_SHA,
            'operations':inspected, 'scope':'closed_agenda_v1_plain_json_value_projection',
            'creation':'public_id_acknowledgment; inserted private copied from owner A shared record',
            'query':'public whitelist id/title/time; full query additionally copies private',
            'assumptions':['trusted Python standard library and Docker controller',
                           'fixed valid calls and plain JSON states validated by capture reader'],
            'general_semantic_truth':False, 'independence_verified':False,
            'timing_and_exception_flows_evaluated':False}


def read_checked_capture(capture, interventions):
    data, audit = read_capture(capture)
    proof = contract(audit, bind_capture(capture, interventions))
    branches = []
    private = audit['intent']['variant'] == 'include_private'
    for branch in data.branches:
        if branch.prefix.source_version != 'closed-agenda-io-v2':
            raise ForecastDataError('checked_agenda_visibility_version_mismatch')
        end = branch.prefix.max_sequence_no + len(branch.observations)
        required = {(1,'agenda-input','agenda-ack'), (2,'agenda-input','agenda-response')}
        if private:
            required.add((2,'protected-source','agenda-response'))
        required = {item for item in required if item[0] <= end}
        actual = [(e.sequence_no,e.source,e.target) for e in branch.transfers if e.relation == 'selection']
        sends = [(e.sequence_no,e.source,e.target) for e in branch.transfers if e.relation == 'send']
        if (set(actual) != required or len(actual) != len(required)
                or sends != ([(3,'agenda-response','receiver')] if end == 3 else [])):
            raise ForecastDataError('checked_agenda_projection_coverage_mismatch')
        edges = []
        for edge in branch.transfers:
            if edge.relation == 'selection':
                allowed = {(1,'agenda-input','agenda-ack'), (2,'agenda-input','agenda-response')}
                if private:
                    allowed.add((2,'protected-source','agenda-response'))
                if (edge.sequence_no,edge.source,edge.target) not in allowed:
                    raise ForecastDataError('checked_agenda_unexpected_projection')
                edge = replace(edge, relation='json_projection', evidence='checked_json_projection', evidence_digest=digest(proof))
            elif edge.relation != 'send':
                raise ForecastDataError('checked_agenda_unexpected_relation')
            edges.append(edge)
        branches.append(replace(branch, transfers=tuple(edges)))
    result = assemble(tuple(branches), related_roots=data.related_roots, provenance=data.provenance)
    return result, {**audit, 'unchecked_dataset_sha':audit['dataset_sha'],
                    'dataset_sha':digest(asdict(result)), 'closed_agenda_projection_evidence':proof}
