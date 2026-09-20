from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import pytest

from hook_monitor.evaluation.flow_lab import replay
from hook_monitor.evaluation.flow_lab.agent import Action
from hook_monitor.evaluation.flow_lab.findings import failure_signatures
from hook_monitor.evaluation.flow_lab.preflight import LabError


class Transport:
    instances = []
    broken_receiver = False

    def __init__(self, _image):
        self.actions = {}
        self.sent = set()
        self.guard_causes = {}
        self.guard_traces = {}
        self.closed = False
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def prepare(self, step, **action):
        self.actions[step] = action
        return step

    def guard(self, command, *, session_id, step_id):
        trace = [['block', 'critical', 'external_http_request', 'source_chunk', 'synthetic reason']]
        self.guard_traces[step_id] = tuple(tuple(row) for row in trace)
        self.guard_causes[step_id] = hashlib.sha256(json.dumps(trace, separators=(',', ':')).encode()).hexdigest()
        return 'deny'

    def send(self, command, **_kwargs):
        self.sent.add(command)
        return True

    def delivery(self, step):
        if self.broken_receiver:
            return 'unknown', 'unknown'
        if step not in self.sent:
            return 'no', 'no'
        return 'yes', 'no' if self.actions[step]['source'] == 'public' else 'yes'


@pytest.fixture
def fake(monkeypatch):
    Transport.instances = []
    monkeypatch.setattr(Transport, 'broken_receiver', False)
    monkeypatch.setattr(replay, 'build_context', lambda _repo: b'synthetic-context')
    monkeypatch.setattr(replay, 'build_image', lambda *args, **kwargs: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(replay, 'check_isolation', lambda image: None)
    monkeypatch.setattr(replay, 'AdaptiveTransport', Transport)


def test_new_environment_controls_evidence_and_durable_result(tmp_path, fake):
    path = tmp_path / 'campaign'
    actions = (Action('public', 'plain'),)
    with replay.ReplayCampaign(path) as campaign:
        first = campaign.run(Path('.'), actions)
        second = campaign.run(Path('.'), actions)
        assert first.observable and second.observable
        assert failure_signatures(first)[0].kind == 'unnecessary_stop'
        assert failure_signatures(first) == failure_signatures(second)
        assert campaign.store.trial_count() == 8  # three controls + one attempt, twice
    assert len(Transport.instances) == 2
    assert all(instance.closed for instance in Transport.instances)
    with replay.ReplayCampaign(path) as campaign:
        assert tuple(asdict(r) for r in campaign.results) == (asdict(first), asdict(second))
    assert len(Transport.instances) == 2  # reading never creates a new trial


def test_interrupted_build_is_preserved_and_never_redispatched(tmp_path, fake, monkeypatch):
    def fail(*args, **kwargs):
        raise LabError('synthetic_build_failure')
    monkeypatch.setattr(replay, 'build_image', fail)
    path = tmp_path / 'campaign'
    with replay.ReplayCampaign(path) as campaign:
        with pytest.raises(LabError, match='synthetic_build_failure'):
            campaign.run(Path('.'), (Action('public', 'plain'),))
    with replay.ReplayCampaign(path) as campaign:
        assert campaign.state['cases'][0]['status'] == 'pending'
        with pytest.raises(LabError, match='replay_requires_reconciliation'):
            campaign.run(Path('.'), (Action('public', 'plain'),))
    assert Transport.instances == []


def test_receiver_fault_is_retained_not_reported_as_protection(tmp_path, fake, monkeypatch):
    monkeypatch.setattr(Transport, 'broken_receiver', True)
    with replay.ReplayCampaign(tmp_path / 'campaign') as campaign:
        result = campaign.run(Path('.'), (Action('protected', 'plain'),))
        assert not result.observable
        assert not result.public_control and not result.protected_control
        assert len(campaign.results) == 1


def test_budgets_cannot_be_reset_by_reopening(tmp_path, fake):
    path = tmp_path / 'campaign'
    with replay.ReplayCampaign(path, max_replays=1) as campaign:
        campaign.run(Path('.'), (Action('public', 'plain'),))
    with replay.ReplayCampaign(path, max_replays=1) as campaign:
        with pytest.raises(LabError, match='replay_budget_exhausted'):
            campaign.run(Path('.'), (Action('public', 'plain'),))
    with pytest.raises(LabError, match='replay_campaign_mismatch'):
        with replay.ReplayCampaign(path, max_replays=2):
            pass


def test_time_budget_survives_restart(tmp_path, fake):
    path = tmp_path / 'campaign'
    with replay.ReplayCampaign(path, seconds=10, clock=lambda: 100):
        pass
    with replay.ReplayCampaign(path, seconds=10, clock=lambda: 111) as campaign:
        with pytest.raises(LabError, match='replay_time_budget_exhausted'):
            campaign.run(Path('.'), (Action('public', 'plain'),))
    assert Transport.instances == []


def test_workflow_shortens_compares_and_reopens_without_new_dispatch(tmp_path, fake, monkeypatch):
    from hook_monitor.evaluation.flow_lab import replay_runner
    monkeypatch.setattr(replay_runner, 'build_context', lambda _repo: b'synthetic-context')
    path = tmp_path / 'workflow'
    actions = (Action('public', 'plain'), Action('protected', 'plain'))
    report = replay_runner.run_workflow(Path('.'), Path('.'), path, actions)
    assert report['minimization'] == 'minimized'
    assert report['comparison']['status'] == 'reproduced'
    assert len(report['regression_candidate']['actions']) == 1
    count = len(Transport.instances)
    assert count == 5
    assert replay_runner.run_workflow(Path('.'), Path('.'), path, actions) == report
    assert len(Transport.instances) == count


def test_workflow_recovers_completed_cases_without_resending(tmp_path, fake, monkeypatch):
    from hook_monitor.evaluation.flow_lab import replay_runner
    monkeypatch.setattr(replay_runner, 'build_context', lambda _repo: b'synthetic-context')
    path = tmp_path / 'workflow'
    actions = (Action('public', 'plain'),)
    first = replay_runner.run_workflow(Path('.'), Path('.'), path, actions)
    # Simulate a crash after all trial evidence was committed, before report checkpoint.
    with replay.ReplayCampaign(path) as campaign:
        del campaign.state['workflow']['report']
        campaign.journal.write(campaign.state)
    count = len(Transport.instances)
    restored = replay_runner.run_workflow(Path('.'), Path('.'), path, actions)
    assert restored == first
    assert len(Transport.instances) == count


def test_search_proposal_is_loaded_readonly_and_validated(tmp_path):
    from hook_monitor.evaluation.flow_lab.replay_runner import search_actions
    from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
    path = tmp_path / 'search'
    state = {'identity': {'spec': {'mode': 'adaptive_search'}},
             'plans': [{'actions': [{'source': 'public', 'encoding': 'plain'}]}]}
    with SearchJournal(path) as journal:
        journal.write(state)
    original = (path / 'search.sqlite3').read_bytes()
    assert search_actions(path, 1) == (Action('public', 'plain'),)
    assert (path / 'search.sqlite3').read_bytes() == original
    with pytest.raises(LabError, match='invalid_search_attempt'):
        search_actions(path, 2)


def test_same_source_reuses_exact_image_and_changed_harness_is_rejected(tmp_path, fake, monkeypatch):
    images = []
    def build(*args, **kwargs):
        value = 'sha256:' + str(len(images) + 1) * 64
        images.append(value)
        return value
    monkeypatch.setattr(replay, 'build_image', build)
    path = tmp_path / 'campaign'
    with replay.ReplayCampaign(path) as campaign:
        first = campaign.run(Path('.'), (Action('public', 'plain'),))
        second = campaign.run(Path('.'), (Action('public', 'plain'),))
        assert first.spec.environment_digest == second.spec.environment_digest
    assert len(images) == 1
    monkeypatch.setattr(replay, 'implementation_revision', lambda: 'changed')
    with pytest.raises(LabError, match='replay_campaign_mismatch'):
        with replay.ReplayCampaign(path):
            pass


def test_cli_defaults_to_documented_time_budget(tmp_path, monkeypatch):
    from hook_monitor.evaluation.flow_lab import replay_runner
    path = tmp_path / "case.json"
    path.write_text(json.dumps({"actions": [{"source": "public", "encoding": "plain"}]}))
    limits = {}
    def run(*args, **kwargs):
        limits.update(kwargs)
        return {"status": "fixture"}
    monkeypatch.setattr(replay_runner, "run_workflow", run)
    assert replay_runner.main(["--before", ".", "--after", ".", "--case", str(path),
                               "--output-directory", str(tmp_path / "out")]) == 0
    assert limits["seconds"] == 600
