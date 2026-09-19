import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, canonical, digest
from research.flow_forecast import mbpp_batch, mbpp_projection as projection
from research.flow_forecast import mbpp_projection_batch as batch, mbpp_projection_evidence as evidence


@pytest.fixture
def fixture_batch(tmp_path, monkeypatch):
    row = {'task_id': 602, 'text': 'Return input.', 'code': 'def answer(value):\n    return value\n',
           'test_setup_code': '', 'test_list': ['assert answer("sample") == "sample"',
                                              'assert answer("other") == "other"', 'assert answer("third") == "third"'],
           'challenge_test_list': []}
    monkeypatch.setattr(mbpp_batch, 'RECORDS', {602: digest(row)})
    monkeypatch.setattr(batch, 'source_records', lambda path: [row])
    monkeypatch.setattr(evidence, 'selected', lambda path: [row])
    monkeypatch.setattr(batch, 'build_context', lambda repository: b'context')
    monkeypatch.setattr(batch, 'build_image', lambda repository, context: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(batch, 'check_isolation', lambda image: None)
    cases = iter(projection.cases(row))
    monkeypatch.setattr(batch, 'execute', lambda *a, **k: canonical(projection.expected(next(cases))).encode())
    out = tmp_path / 'interventions'
    batch.run(tmp_path, tmp_path / 'source', 602, out)
    return out


def test_saved_interventions_preserve_all_cases(fixture_batch, tmp_path):
    verified = evidence.read_interventions(fixture_batch, tmp_path / 'source')
    assert verified['report']['trial_charges'] == 9
    base, private, inputs = verified['report']['results']
    assert base['public_output_sha'] == private['public_output_sha']
    assert base['private_output_sha'] != private['private_output_sha']
    assert base['public_output_sha'] != inputs['public_output_sha']
    assert verified['report']['semantic_truth_promoted'] is False


@pytest.mark.parametrize('file', ['reservation-1', 'result-1', 'container-1', 'implementation', 'failure', 'reservation-10'])
def test_drift_failure_or_extra_attempt_rejected(fixture_batch, tmp_path, file):
    (fixture_batch / (file + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        evidence.read_interventions(fixture_batch, tmp_path / 'source')


def test_duplicate_json_keys_rejected_even_after_observation_hash_updated(fixture_batch, tmp_path):
    p = fixture_batch / 'observation-1.json'
    raw = p.read_bytes().replace(b'{', b'{"initial":42,', 1)
    p.write_bytes(raw)
    q = fixture_batch / 'result-1.json'
    result = json.loads(q.read_text())
    result['observation_sha'] = hashlib.sha256(raw).hexdigest()
    q.write_text(canonical(result))
    report_path = fixture_batch / 'report.json'
    report = json.loads(report_path.read_text())
    report['results'][0] = result
    report_path.write_text(canonical(report))
    with pytest.raises(ForecastDataError):
        evidence.read_interventions(fixture_batch, tmp_path / 'source')
