from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from research.flow_forecast import mbpp_batch, mbpp_import as importer, task_catalog
from research.flow_forecast.mbpp_transport import call_for, dispatch_script, expected_output, state
from test_flow_forecast_agenda_import import capture as agenda_capture


@pytest.fixture
def reference(monkeypatch):
    row = {'task_id': 602, 'text': 'Return input.', 'code': 'def answer(value):\n    return value\n',
           'test_setup_code': '', 'test_list': ['assert answer("sample") == "sample"'] * 3,
           'challenge_test_list': []}
    monkeypatch.setattr(mbpp_batch, 'RECORDS', {602: digest(row)})
    monkeypatch.setattr(mbpp_batch, 'selected', lambda path: [row])
    monkeypatch.setattr(importer, 'selected', lambda path: [row])
    return row


def capture(path, reference, variant='public', root='1' * 32):
    # Reuse the controller/receiver fixture envelope, replacing all task evidence.
    intent, execution, report = agenda_capture(path, variant, root)
    intent['task'] = 'pinned_mbpp_dispatch_v1'
    intent['origin'] = {'source_commit': importer.COMMIT, 'source_sha': importer.SOURCE_SHA,
                        'candidate': mbpp_batch.checked(reference), 'case_index': 0}
    execution['intent_sha'] = report['intent_sha'] = digest(intent)
    report['execution_sha'] = digest(execution)
    def save(name, value):
        (path / (name + '.json')).write_text(canonical(value))
    charged = 0
    for condition in report['conditions']:
        charged += 3
        for row in condition['steps']:
            n = row['number']
            row['call'] = call_for(reference, n, variant)
            row['call_sha'] = digest(row['call'])
            code = dispatch_script(reference, row['call'], n, variant, row['receiver_address'], row['step_id'])
            row['script_sha'] = hashlib.sha256(code.encode()).hexdigest()
            if row['dispatched']:
                observation = row['observation']
                observation['call_sha'], observation['script_sha'] = row['call_sha'], row['script_sha']
                observation['dispatch'] = {'call': row['call'], 'before': state(reference, n > 1),
                    'after': state(reference, True), 'output': expected_output(reference, n, variant) if n < 3 else {'delivered': True}}
                observation['observer'] = {'state': state(reference, True), 'value': expected_output(reference, min(n, 2), variant)}
                if n == 3:
                    body = row['call']['arguments']['content'].encode()
                    observation['receiver'].update(body_sha=hashlib.sha256(body).hexdigest(), body_size=len(body))
            charged += 1
            save(f'reservation-{charged}', {key: row[key] for key in importer.IDENTITY})
            save(f'{condition["mode"]}-step-{n}', row)
    for name, value in [('intent', intent), ('execution', execution), ('report', report)]:
        save(name, value)
    return intent, execution, report


def test_actual_io_boundary_and_unknown_causality(reference, tmp_path):
    datasets = []
    for variant in ('public', 'include_private'):
        path = tmp_path / variant
        capture(path, reference, variant)
        data, audit = importer.read_capture(path, tmp_path / 'source')
        datasets.append(data)
        assert len(data.branches) == 6 and audit['generator_evidence'] is None
        assert {label_future(branch, 4).protected_arrival for branch in data.branches} == {'unknown'}
        for prefix in data.prefixes:
            assert prefix.source_version == 'pinned-mbpp-io-v1'
            assert all(obj.object_id != 'mbpp-record' for obj in prefix.objects)
            if prefix.max_sequence_no >= 1:
                assert prefix.observations[0].inputs == ('mbpp-input',)
                assert prefix.observations[0].outputs == ('mbpp-ack',)
            if prefix.max_sequence_no == 2:
                assert ('protected-source' in prefix.observations[1].inputs) == (variant == 'include_private')
    for cut in (0, 1):
        assert next(p.model_input() for p in datasets[0].prefixes if p.max_sequence_no == cut) == next(
            p.model_input() for p in datasets[1].prefixes if p.max_sequence_no == cut)


@pytest.mark.parametrize('part', ['origin', 'case', 'case-bool', 'call', 'receiver', 'state', 'guard', 'charges', 'generator'])
def test_rehashed_inconsistent_evidence_is_rejected(reference, tmp_path, part):
    intent, execution, report = capture(tmp_path / 'capture', reference, 'include_private')
    intent, execution, report = deepcopy(intent), deepcopy(execution), deepcopy(report)
    row = report['conditions'][0]['steps'][2]
    if part == 'origin':
        intent['origin']['candidate']['record_sha'] = '0' * 64
    elif part == 'case':
        intent['origin']['case_index'] = 1
    elif part == 'case-bool':
        intent['origin']['case_index'] = False
    elif part == 'call':
        row['call']['arguments']['content'] = 'other'
        row['call_sha'] = digest(row['call'])
    elif part == 'receiver':
        row['observation']['receiver']['body_sha'] = '0' * 64
    elif part == 'state':
        row['observation']['observer']['state']['result'] = 'wrong'
    elif part == 'guard':
        row['receipt']['receipt_count'] = 0
    elif part == 'generator':
        intent['generator'] = {'model': 'invented'}
    else:
        report['trial_charges'] = 11
    execution['intent_sha'] = report['intent_sha'] = digest(intent)
    report['execution_sha'] = digest(execution)
    with pytest.raises(ForecastDataError):
        importer.dataset(intent, execution, report, reference)


@pytest.mark.parametrize('extra', ['failure', 'reservation-13', 'observe-step-4', 'enforce-guard-4'])
def test_failed_or_unaccounted_trials_rejected(reference, tmp_path, extra):
    path = tmp_path / 'capture'
    capture(path, reference)
    (path / (extra + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        importer.read_capture(path, tmp_path / 'source')


def test_variants_share_collection_group_and_source_binding(reference, tmp_path):
    paths = []
    for number, variant in enumerate(('public', 'include_private'), 1):
        path = tmp_path / variant
        capture(path, reference, variant, str(number) * 32)
        paths.append(str(path))
    inputs = tmp_path / 'inputs.json'
    inputs.write_text(json.dumps(paths))
    out = tmp_path / 'collection'
    task_catalog.main(['--mbpp-captures', str(inputs), '--mbpp-source', str(tmp_path / 'source'), '--output', str(out)])
    data, _, audit = task_catalog.read_collection(out)
    assert len(data.branches) == 12 and audit['grouped_root_count'] == 1
    assert audit['independence_verified'] is False and audit['prior_nonuse_verified'] is False
    assert len(audit['mbpp_captures']) == 2
    with pytest.raises(ForecastDataError, match='duplicate_collection_root'):
        task_catalog.collect_mbpp_captures((Path(paths[0]), Path(paths[0])), tmp_path / 'source')
