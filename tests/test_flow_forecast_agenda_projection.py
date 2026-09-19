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
