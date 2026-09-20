from copy import deepcopy
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import agenda_batch, agenda_projection as projection


@pytest.mark.parametrize('case', projection.cases(), ids=lambda c: c['name'])
def test_actual_closed_api_dispatch_matches_intervention_oracle(case):
    # Execute only the internally generated standalone source in a fresh namespace.
    import contextlib
    import io
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(compile(projection.script(case), '<closed-agenda-projection>', 'exec'), {})
    row = projection.verify(case, stdout.getvalue().encode())
    assert row['calls_observed'] == 3
    actual = json.loads(stdout.getvalue())
    assert actual['final']['B'] == actual['initial']['B']
    assert 'private' not in actual['steps'][1]['output']


def test_private_changes_do_not_change_public_query():
    rows = [projection.verify(case, canonical(projection.expected(case)).encode()) for case in projection.cases()]
    assert rows[0]['public_output_sha'] == rows[1]['public_output_sha'] == rows[2]['public_output_sha']
    assert rows[0]['private_output_sha'] != rows[1]['private_output_sha']
    assert rows[0]['private_output_sha'] == rows[2]['private_output_sha']
    assert all(rows[i]['public_output_sha'] != rows[0]['public_output_sha'] for i in (3, 4))


def test_mismatched_observation_and_unreviewed_source_rejected(monkeypatch):
    case = projection.cases()[0]
    value = projection.expected(case)
    value['steps'][1]['output']['private'] = 'unexpected'
    with pytest.raises(LabError, match='oracle_mismatch'):
        projection.verify(case, canonical(value).encode())
    monkeypatch.setattr(projection, 'API_SHA', '0'*64)
    with pytest.raises(LabError, match='source_changed'):
        projection.script(case)


def test_external_case_rejected():
    case = deepcopy(projection.cases()[0])
    case['initial']['A']['shared']['private'] = 'arbitrary'
    with pytest.raises(LabError, match='unknown_agenda_projection'):
        projection.script(case)


def test_failed_projection_batch_keeps_all_reserved_calls(monkeypatch, tmp_path):
    monkeypatch.setattr(agenda_batch, 'build_context', lambda *a: b'fixture')
    monkeypatch.setattr(agenda_batch, 'build_image', lambda *a, **k: 'fixture')
    monkeypatch.setattr(agenda_batch, 'check_isolation', lambda *a: None)
    def fail(*a, **k):
        raise LabError('fixture_failed')
    monkeypatch.setattr(agenda_batch, 'execute', fail)
    output = tmp_path / 'failed'
    with pytest.raises(LabError, match='fixture_failed'):
        agenda_batch.run(tmp_path, output, suite='projection')
    assert json.loads((output/'failure.json').read_text())['trial_reservations'] == 3
    assert not (output/'report.json').exists()


@pytest.fixture
def captured_interventions(monkeypatch, tmp_path):
    import contextlib
    import io
    monkeypatch.setattr(agenda_batch, 'build_context', lambda *a: b'fixture')
    monkeypatch.setattr(agenda_batch, 'build_image', lambda *a, **k: 'sha256:' + 'a'*64)
    monkeypatch.setattr(agenda_batch, 'check_isolation', lambda *a: None)
    def execute(image, source, **kwargs):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(source, '<closed-agenda-test>', 'exec'), {})
        return out.getvalue().encode()
    monkeypatch.setattr(agenda_batch, 'execute', execute)
    output = tmp_path / 'interventions'
    agenda_batch.run(tmp_path, output, suite='projection')
    return output


def test_saved_interventions_revalidate_exact_case_calls_and_outputs(captured_interventions):
    from research.flow_forecast.agenda_projection_evidence import read_interventions
    result = read_interventions(captured_interventions)
    assert result['report']['trial_charges'] == 15
    assert result['report']['semantic_truth_promoted'] is False


@pytest.mark.parametrize('part', ['observation-1','result-1','reservation-1','container-1','failure','reservation-16'])
def test_saved_interventions_reject_drift_and_extra_attempts(captured_interventions, part):
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
    from research.flow_forecast.agenda_projection_evidence import read_interventions
    (captured_interventions / (part + '.json')).write_text('{}')
    with pytest.raises(ForecastDataError):
        read_interventions(captured_interventions)


def test_binding_records_different_images_without_claiming_equivalence(captured_interventions, monkeypatch, tmp_path):
    import hashlib
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
    from research.flow_forecast import agenda_projection_evidence as evidence
    from test_flow_forecast_agenda_import import capture
    path = tmp_path / 'capture'
    capture(path)
    _, audit = evidence.read_capture(path)
    audit['execution']['context_sha'] = hashlib.sha256(b'fixture').hexdigest()
    audit['execution']['image'] = 'sha256:' + 'f'*64
    monkeypatch.setattr(evidence, 'read_capture', lambda *a: (None, audit))
    proof = evidence.bind_capture(path, captured_interventions)
    assert proof['identical_image_verified'] is False
    assert proof['query_observations_bound'] == 2
    assert proof['semantic_truth_promoted'] is False
    audit['execution']['context_sha'] = '0'*64
    with pytest.raises(ForecastDataError, match='context_mismatch'):
        evidence.bind_capture(path, captured_interventions)


def test_rehashed_observation_with_duplicate_keys_is_rejected(captured_interventions):
    import hashlib
    from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
    from research.flow_forecast.agenda_projection_evidence import read_interventions
    path = captured_interventions / 'observation-1.json'
    original = path.read_bytes()
    modified = b'{"initial":{"conflicting":"value"},' + original[1:]
    path.write_bytes(modified)
    result_path = captured_interventions / 'result-1.json'
    result = json.loads(result_path.read_text())
    result['observation_sha'] = hashlib.sha256(modified).hexdigest()
    result_path.write_text(canonical(result))
    report_path = captured_interventions / 'report.json'
    report = json.loads(report_path.read_text())
    report['results'][0] = result
    report_path.write_text(canonical(report))
    with pytest.raises(ForecastDataError):
        read_interventions(captured_interventions)
