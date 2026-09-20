from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble, read_dataset, write_dataset
from hook_monitor.evaluation.flow_forecast.executor import SendResult, execute_branch, reference_suite
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from hook_monitor.evaluation.flow_forecast.runner import expected_body


class FixtureSender:
    def __init__(self):
        self.calls = []

    def send(self, *, source, encoding, body, mode):
        assert body == expected_body(source, encoding)
        self.calls.append((source, encoding, body, mode))
        denied = source == 'protected'
        executed = not denied or mode == 'observe'
        return SendResult('deny' if denied else 'allow', executed, 'yes' if executed else 'no',
                          'yes' if executed and denied else 'no', True, executed,
                          digest([source, encoding, body.hex(), mode]))


@pytest.mark.parametrize('variant', ['initial', 'alternate'])
def test_generated_futures_have_paired_controls_and_before_after_output_prefixes(tmp_path, variant):
    sender = FixtureSender()
    rows = reference_suite(sender, environment_version='test-v1', task_variant=variant)
    assert len(rows) == 24
    assert len(sender.calls) == 8
    dataset = assemble(rows)
    assert len(dataset.prefixes) == 8
    before = [b for b in rows if b.prefix.max_sequence_no == 1]
    for source in ('private-source', 'public-source'):
        group = [b for b in before if b.prefix.observations[0].inputs == (source,)]
        assert len({b.prefix.snapshot_digest for b in group}) == 1
        assert {b.branch_id for b in group} == {'local', 'send', 'save_then_send'}
    write_dataset(dataset, tmp_path / 'artifact')
    assert read_dataset(tmp_path / 'artifact') == dataset
    labels = dataset.summary()['label_counts']
    assert labels['enforce/4/unknown'] >= 2
    assert labels['observe/4/yes'] >= 2


def test_local_branch_never_calls_sender():
    sender = FixtureSender()
    rows = execute_branch(sender, root_case_id='case', source='protected', encoding='base64',
                          branch='local', mode='enforce', environment_version='test-v1')
    assert sender.calls == []
    assert all(row.termination == 'completed' for row in rows)


def test_unknown_receiver_does_not_create_truth_edge():
    class UnknownSender:
        def send(self, **kwargs):
            return SendResult('allow', True, 'unknown', 'unknown', False, False, 'a' * 64)
    rows = execute_branch(UnknownSender(), root_case_id='case', source='public', encoding='plain',
                          branch='send', mode='observe', environment_version='test-v1')
    assert all(row.termination == 'unknown' and not row.receiver_complete for row in rows)
    assert all(not row.receiver_arrivals for row in rows)


def test_mismatched_receiver_content_does_not_establish_known_route():
    class WrongReceiver:
        def send(self, **kwargs):
            return SendResult('allow', True, 'yes', 'no', True, True, 'a' * 64)
    rows = execute_branch(WrongReceiver(), root_case_id='case', source='protected', encoding='plain',
                          branch='send', mode='observe', environment_version='test-v1')
    assert all(row.transfers[-1].evidence == 'unknown' for row in rows)


def test_contradictory_send_observation_is_rejected():
    with pytest.raises(ForecastDataError):
        SendResult('deny', False, 'yes', 'yes', True, False, 'a' * 64)
    with pytest.raises(ForecastDataError):
        replace(SendResult('allow', True, 'yes', 'no', True, True, 'a' * 64), complete=True, received='unknown')


def test_checked_transport_rejects_changed_sender_bytes_before_dispatch(monkeypatch):
    from hook_monitor.evaluation.flow_forecast.runner import CheckedTransport
    from hook_monitor.evaluation.flow_lab.transport import FixedTransport
    transport = CheckedTransport('sha256:' + 'a' * 64)
    transport.address = '172.22.0.2'
    original = FixedTransport.prepare
    def altered(self, step_id, **kwargs):
        return original(self, step_id, **kwargs).replace('FLOW_LAB_PUBLIC_TEXT', 'OTHER_PUBLIC_TEXT')
    monkeypatch.setattr(FixedTransport, 'prepare', altered)
    with pytest.raises(ForecastDataError, match='inspected_sender_bytes_mismatch'):
        transport.prepare('a' * 32, source='public')


def test_expired_or_mismatched_send_cannot_reach_transport(tmp_path):
    from hook_monitor.evaluation.flow_forecast.runner import LabSender
    class NoAccess:
        def __getattr__(self, name):
            raise AssertionError('unexpected side effect')
    sender = LabSender(NoAccess(), NoAccess(), NoAccess(), tmp_path, deadline=0)
    with pytest.raises(ForecastDataError, match='forecast_time_budget_exhausted'):
        sender.send(source='public', encoding='plain', body=expected_body('public', 'plain'), mode='observe')
    with pytest.raises(ForecastDataError, match='unexpected_synthetic_bytes'):
        sender.send(source='public', encoding='plain', body=b'UNEXPECTED', mode='observe')


def test_existing_generation_output_is_never_redispatched(tmp_path, monkeypatch):
    from hook_monitor.evaluation.flow_forecast import runner
    path = tmp_path / 'unfinished'
    path.mkdir()
    (path / 'intent.json').write_text('pending')
    monkeypatch.setattr(runner, 'build_context', lambda *_: pytest.fail('must not build or dispatch'))
    with pytest.raises(FileExistsError):
        runner.run(tmp_path, path)
    assert (path / 'intent.json').read_text() == 'pending'


def test_encoding_variants_share_root_split_but_known_task_is_visible():
    values = tuple(row for variant in ('initial', 'alternate')
                   for row in reference_suite(FixtureSender(), environment_version='test-v1', task_variant=variant))
    dataset = assemble(values)
    assert dataset.summary()['root_count'] == 2
    for source in ('private-source', 'public-source'):
        prefixes = [p for p in dataset.prefixes if p.observations[0].inputs == (source,)]
        assert {p.model_input()['task_kind'] for p in prefixes} == {'plain_http', 'base64_http'}
        assert len({dataset.split.partition(p) for p in prefixes}) == 1
