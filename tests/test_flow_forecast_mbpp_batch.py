import hashlib
import json

import pytest

from hook_monitor.evaluation.flow_forecast.prefix import canonical, digest
from hook_monitor.evaluation.flow_lab.preflight import LabError
from research.flow_forecast import mbpp_batch as batch


@pytest.fixture
def source(tmp_path, monkeypatch):
    rows = [{'task_id': number, 'text': 'Return input.', 'code': 'def answer(value):\n    return value\n',
             'test_setup_code': '', 'test_list': ['assert answer(1) == 1', 'assert answer([2]) == [2]',
                                                'assert answer("three") == "three"'],
             'challenge_test_list': []} for number in (602, 603, 604)]
    raw = ('\n'.join(canonical(row) for row in rows) + '\n').encode()
    path = tmp_path / 'test-source.jsonl'
    path.write_bytes(raw)
    monkeypatch.setattr(batch, 'SOURCE_SHA', hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(batch, 'RECORDS', {row['task_id']: digest(row) for row in rows})
    monkeypatch.setattr(batch, 'source_provenance', lambda root: {'fixed': True})
    monkeypatch.setattr(batch, 'build_context', lambda repository: b'context')
    monkeypatch.setattr(batch, 'build_image', lambda repository, context: 'image')
    monkeypatch.setattr(batch, 'check_isolation', lambda image: None)
    return path, rows


def test_all_nine_calls_reserved_before_execution_and_observed(source, tmp_path, monkeypatch):
    path, rows = source
    out = tmp_path / 'batch'
    names = []
    def execute(image, script, *, name):
        number = len(names) + 1
        assert (out / f'reservation-{number}.json').is_file()
        assert json.loads((out / f'container-{number}.json').read_text())['name'] == name
        names.append(name)
        return [b'1', b'[2]', b'"three"'][(number - 1) % 3]
    monkeypatch.setattr(batch, 'execute', execute)
    result = batch.run(tmp_path, path, out)
    assert result['trial_charges'] == 9
    assert result['all_oracles_matched'] is True
    assert result['receiver_observed'] is False
    assert result['independent_new_tasks_accepted'] == 0
    assert len(set(names)) == 9
    assert len(list(out.glob('observation-*.json'))) == 9


def test_wrong_result_is_retained_and_not_silently_retried(source, tmp_path, monkeypatch):
    path, _ = source
    monkeypatch.setattr(batch, 'execute', lambda *args, **kwargs: b'false')
    out = tmp_path / 'batch'
    result = batch.run(tmp_path, path, out)
    assert result['status'] == 'completed'
    assert result['all_oracles_matched'] is False
    assert result['trial_charges'] == 9
    assert (out / 'observation-1.json').read_bytes() == b'false'


def test_execution_failure_preserves_charge_and_stops(source, tmp_path, monkeypatch):
    path, _ = source
    def fail(*args, **kwargs):
        raise LabError('container_timeout')
    monkeypatch.setattr(batch, 'execute', fail)
    out = tmp_path / 'batch'
    with pytest.raises(LabError, match='container_timeout'):
        batch.run(tmp_path, path, out)
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 1
    assert not (out / 'reservation-2.json').exists()
    assert not (out / 'report.json').exists()


def test_modified_reference_rejected_before_script_creation(source):
    _, rows = source
    rows[0]['code'] += 'open("unexpected", "w")\n'
    with pytest.raises(LabError, match='unreviewed_mbpp_record'):
        batch.script(rows[0], 0)


def test_source_mutation_rejected_before_output_creation(source, tmp_path):
    path, _ = source
    path.write_bytes(path.read_bytes() + b' ')
    out = tmp_path / 'batch'
    with pytest.raises(LabError, match='mbpp_source_digest_mismatch'):
        batch.run(tmp_path, path, out)
    assert not out.exists()


def test_expired_batch_stops_before_any_execution(source, tmp_path):
    path, _ = source
    clock = iter([0, 181, 181])
    out = tmp_path / 'batch'
    with pytest.raises(LabError, match='mbpp_batch_budget_exhausted'):
        batch.run(tmp_path, path, out, clock=lambda: next(clock))
    assert json.loads((out / 'failure.json').read_text())['trial_reservations'] == 0


def test_oracle_uses_json_types_and_rejects_duplicate_keys(source):
    _, rows = source
    assert batch.verify(rows[0], 0, b'true')['oracle_matched'] is False
    with pytest.raises(ValueError):
        batch.verify(rows[0], 0, b'{"x":1,"x":2}')
