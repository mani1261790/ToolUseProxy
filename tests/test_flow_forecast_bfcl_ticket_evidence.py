from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical
from research.flow_forecast import bfcl_ticket_interventions as runner, bfcl_ticket_evidence as evidence

SOURCE = '# synthetic fixture, never executed\n'


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    sha = hashlib.sha256(SOURCE.encode()).hexdigest()
    monkeypatch.setattr(runner, 'SOURCE_SHA', sha)
    monkeypatch.setattr(evidence, 'SOURCE_SHA', sha)
    monkeypatch.setattr(runner, 'build_context', lambda *a: b'fixture context')
    monkeypatch.setattr(runner, 'build_image', lambda *a, **k: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(runner, 'check_isolation', lambda *a: None)
    rows = iter(runner.cases())
    monkeypatch.setattr(runner, 'execute', lambda *a, **k: canonical(next(rows)['expected']).encode())
    source = tmp_path / 'source.py'
    source.write_text(SOURCE)
    output = tmp_path / 'interventions'
    runner.run(Path(runner.__file__).resolve().parents[2], source, output)
    return output


def test_exact_intervention_evidence(recorded):
    result = evidence.read_interventions(recorded, SOURCE)
    assert len(result['observations']) == 5
    assert result['report']['trial_charges'] == 20


@pytest.mark.parametrize('name', ['reservation-1','observation-2','result-3','implementation','report'])
def test_modified_evidence_rejected(recorded, name):
    (recorded / (name + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        evidence.read_interventions(recorded, SOURCE)


@pytest.mark.parametrize('name', ['failure','reservation-6','observation-6','result-6'])
def test_extra_attempts_rejected(recorded, name):
    (recorded / (name + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        evidence.read_interventions(recorded, SOURCE)


@pytest.mark.parametrize('variant', ['public','include_private'])
def test_binding_requires_matching_context_state_and_output(recorded, monkeypatch, variant):
    baseline = runner.cases()[0]['expected']
    execution = json.loads((recorded / 'execution.json').read_text())
    original = {'intent':{'variant':variant,'root':'1'*32}, 'execution':execution,
                'report':{'conditions':[{'steps':[{'number':2,'dispatched':True,
                    'observation':{'dispatch':{'before':baseline['state'],'after':baseline['state'],
                    'output':baseline['outputs'][1 if variant == 'public' else 2]}}}]}]}}
    original = deepcopy(original)
    monkeypatch.setattr(evidence, 'read_capture', lambda *a: (None, original))
    result = evidence.bind_capture(Path('unused'),recorded,SOURCE)
    assert result['query_observations_bound'] == 1 and result['semantic_truth_promoted'] is False
    original['execution']['context_sha'] = 'b'*64
    with pytest.raises(ForecastDataError, match='context_mismatch'):
        evidence.bind_capture(Path('unused'),recorded,SOURCE)
    original['execution']['context_sha'] = execution['context_sha'] = hashlib.sha256(b'fixture context').hexdigest()
    original['report']['conditions'][0]['steps'][0]['observation']['dispatch']['output'] = 'changed'
    with pytest.raises(ForecastDataError, match='baseline_mismatch'):
        evidence.bind_capture(Path('unused'),recorded,SOURCE)
