from dataclasses import asdict, replace
import json

import pytest

from hook_monitor.evaluation.flow_lab.issue_runner import read_proposals
from hook_monitor.evaluation.flow_lab.outbox import GitHubClient, Outbox
from hook_monitor.evaluation.flow_lab.preflight import LabError
from hook_monitor.evaluation.flow_lab.proposal import IssueProposal, document, parse_proposal
from hook_monitor.evaluation.flow_lab.search_state import SearchJournal
from tooluseproxy.pilot_worker import SyncFailure


def item(revision='a', step='b', **kwargs):
    return IssueProposal(
        kind=kwargs.pop('kind', 'unnecessary_stop'),
        action={'source': 'public', 'encoding': 'plain', 'representation': 'literal', 'client': 'urllib'},
        detector_revision='source-' + revision * 64, run_id='a' * 32, step_id=step * 32,
        cause_digest=None, outcomes=('unnecessary_stop',), finding_observed=True,
        controls_passed=True, **kwargs,
    )


class Client:
    def __init__(self):
        self.records = []
        self.notes = {}
        self.creates = 0
        self.posts = 0
        self.failure = None
        self.auth_failure = False

    def authenticate(self):
        if self.auth_failure:
            raise SyncFailure('unauthenticated')

    def issues(self, repository):
        return list(self.records)

    def comments(self, repository, number):
        return list(self.notes.get(number, []))

    def create(self, repository, title, body):
        self.creates += 1
        if self.failure == 'before_write':
            raise SyncFailure('ambiguous')
        value = {'number': len(self.records)+1, 'body': body, 'state': 'open'}
        self.records.append(value)
        if self.failure == 'after_write':
            raise SyncFailure('ambiguous')
        return value

    def comment(self, repository, number, body):
        self.posts += 1
        value = {'id': self.posts, 'body': body}
        self.notes.setdefault(number, []).append(value)
        if self.failure == 'after_comment':
            raise SyncFailure('ambiguous')
        return value


def test_revisions_bind_to_one_issue_and_reenqueue_does_not_duplicate(tmp_path):
    client = Client()
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        first, second = item(), item('c', 'd')
        assert first.problem_key == second.problem_key
        assert first.delivery_key != second.delivery_key
        assert outbox.enqueue(first) == 1
        assert outbox.enqueue(first) == 0
        outbox.enqueue(second)
        assert outbox.sync(client=client)['states'] == {'sent': 2}
        assert client.creates == 1 and client.posts == 1
        assert outbox.sync(client=client)['sent'] == 0
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        assert outbox.sync(client=client)['sent'] == 0
    assert client.creates == 1 and client.posts == 1


def test_unknown_post_reconciles_after_restart_without_resending(tmp_path):
    client = Client()
    client.failure = 'after_write'
    path = tmp_path / 'outbox'
    with Outbox(path, 'owner/repository') as outbox:
        outbox.enqueue(item())
        assert outbox.sync(client=client)['states'] == {'in_flight': 1}
    client.failure = None
    with Outbox(path, 'owner/repository') as outbox:
        assert outbox.sync(client=client)['states'] == {'sent': 1}
    assert client.creates == 1


def test_absence_is_not_proof_to_retry_unknown_write_or_following_version(tmp_path):
    client = Client()
    client.failure = 'before_write'
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        outbox.enqueue(item('c', 'd'))
        for _ in range(3):
            assert outbox.sync(client=client)['states'] == {'in_flight': 1, 'pending': 1}
        assert client.creates == 1 and client.posts == 0


def test_unknown_comment_is_read_back_not_reposted(tmp_path):
    client = Client()
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        outbox.sync(client=client)
        client.failure = 'after_comment'
        outbox.enqueue(item('c', 'd'))
        assert outbox.sync(client=client)['states'] == {'in_flight': 1, 'sent': 1}
        assert outbox.sync(client=client)['states'] == {'sent': 2}
    assert client.posts == 1


def test_auth_failure_is_safe_to_retry_and_does_not_claim_delivery(tmp_path):
    client = Client()
    client.auth_failure = True
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        assert outbox.sync(client=client)['error'] == 'unauthenticated'
        assert client.creates == 0
        client.auth_failure = False
        assert outbox.sync(client=client)['states'] == {'sent': 1}


def test_explicit_binding_uses_existing_issue_without_reopening_it(tmp_path):
    client = Client()
    client.records = [{'number': 140, 'body': 'existing issue', 'state': 'closed'}]
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        outbox.bind(item().problem_key, 140)
        assert outbox.sync(client=client)['states'] == {'sent': 1}
        with pytest.raises(SyncFailure):
            outbox.bind(item().problem_key, 141)
    assert client.creates == 0 and client.posts == 1
    assert client.records[0]['state'] == 'closed'


def test_duplicate_remote_markers_never_choose_an_arbitrary_issue(tmp_path):
    client = Client()
    _, body = document(item())
    client.records = [{'number': n, 'body': body} for n in (1, 2)]
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        assert outbox.sync(client=client)['states'] == {'pending': 1}
    assert client.creates == 0 and client.posts == 0


def test_unknown_and_unidentified_documents_are_supported():
    proposal = replace(item(), kind='incomplete_observation', outcomes=('incomplete_observation',),
                       controls_passed=False, cause_digest=None, pending=True)
    title, body = document(proposal)
    assert '観測不足' in title and '未特定' in body and '成否は不明' in body
    assert proposal.problem_key == replace(proposal, detector_revision='source-'+'f'*64).problem_key


@pytest.mark.parametrize('field,value', [
    ('detector_revision', 'secret-PRIVATE_VALUE'), ('run_id', '/private/path'),
    ('cause_digest', 'PRIVATE_VALUE'), ('outcomes', ['PRIVATE_VALUE']),
    ('kind', 'PRIVATE_VALUE'), ('controls_passed', 'PRIVATE_VALUE'),
])
def test_free_text_cannot_enter_shared_documents(field, value):
    value_dict = json.loads(json.dumps(asdict(item())))
    value_dict[field] = value
    with pytest.raises(LabError):
        parse_proposal(value_dict)


def test_modified_queued_content_is_rejected_before_post(tmp_path):
    client = Client()
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        payload = asdict(item()) | {'raw_payload': 'PRIVATE_VALUE'}
        outbox.db.execute('UPDATE proposals SET payload=?', (json.dumps(payload),))
        assert outbox.sync(client=client)['states'] == {'rejected': 1}
    assert client.creates == 0 and client.posts == 0


def test_destination_change_symlink_and_unrelated_directory_are_rejected(tmp_path):
    path = tmp_path / 'outbox'
    with Outbox(path, 'owner/repository'):
        pass
    with pytest.raises(LabError, match='issue_destination_mismatch'):
        Outbox(path, 'owner/other')
    link = tmp_path / 'link'
    link.symlink_to(path, target_is_directory=True)
    with pytest.raises(LabError, match='unsafe_issue_outbox'):
        Outbox(link, 'owner/repository')
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (unrelated / 'keep.txt').write_text('keep')
    with pytest.raises(LabError, match='unrelated_issue_outbox'):
        Outbox(unrelated, 'owner/repository')
    assert (unrelated / 'keep.txt').read_text() == 'keep'


def test_pending_replay_is_proposed_without_reading_or_sharing_raw_content(tmp_path):
    path = tmp_path / 'campaign'
    state = {'identity': {'kind': 'synthetic-replay-v1'}, 'cases': [{
        'status': 'pending', 'actions': [item().action], 'run_id': 'a'*32,
        'detector_revision': 'source-'+'a'*64, 'raw_payload': 'PRIVATE_VALUE'}]}
    with SearchJournal(path) as journal:
        journal.write(state)
    before = (path / 'search.sqlite3').read_bytes()
    result = read_proposals(path)
    assert len(result) == 1 and result[0].pending
    assert 'PRIVATE_VALUE' not in document(result[0])[1]
    assert (path / 'search.sqlite3').read_bytes() == before


def test_shared_github_client_sends_structured_json_only(monkeypatch):
    calls = []
    def run(command, **kwargs):
        from types import SimpleNamespace
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"number": 1}', stderr='')
    monkeypatch.setattr('subprocess.run', run)
    title, body = document(item())
    GitHubClient().create('owner/repository', title, body)
    command, kwargs = calls[0]
    assert command == ['gh', 'api', '--hostname', 'github.com', '--method', 'POST', 'repos/owner/repository/issues', '--input', '-']
    assert json.loads(kwargs['input']) == {'title': title, 'body': body}


def test_simultaneous_workers_are_excluded(tmp_path):
    path = tmp_path / 'outbox'
    with Outbox(path, 'owner/repository') as first, Outbox(path, 'owner/repository') as second:
        second.enqueue(item())
        with first.lease(), pytest.raises(LabError, match='issue_sync_busy'):
            second.sync(client=Client())


def test_large_github_comment_ids_are_successful(tmp_path):
    client = Client()
    client.records = [{'number': 140, 'body': 'existing issue', 'state': 'open'}]
    def comment(repository, number, body):
        return {'id': 5725394067, 'body': body}
    client.comment = comment
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        outbox.bind(item().problem_key, 140)
        assert outbox.sync(client=client)['status'] == 'ok'


def test_malformed_success_response_stays_unknown(tmp_path):
    client = Client()
    client.create = lambda *args: None
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        report = outbox.sync(client=client)
        assert report['status'] == 'pending' and report['states'] == {'in_flight': 1}


def test_truncated_github_listing_is_not_treated_as_absence():
    class Pages(GitHubClient):
        def _run(self, args, **kwargs):
            return [{'number': 1}] * 100
    with pytest.raises(SyncFailure, match='invalid'):
        Pages().issues('owner/repository')


def test_finding_status_cannot_contradict_closed_observations():
    with pytest.raises(LabError, match='contradictory_synthetic_proposal'):
        replace(item(), finding_observed=False)


def test_unknown_rows_do_not_starve_other_problems(tmp_path):
    client = Client()
    client.failure = 'before_write'
    with Outbox(tmp_path / 'outbox', 'owner/repository') as outbox:
        outbox.enqueue(item())
        outbox.sync(client=client, limit=1)
        outbox.enqueue(replace(item(step='c'), kind='hook_gap', outcomes=('hook_gap',)))
        client.failure = None
        report = outbox.sync(client=client, limit=1)
        assert report['sent'] == 1
        assert report['states'] == {'in_flight': 1, 'sent': 1}


def test_later_non_observation_keeps_same_problem_identity():
    original = item()
    later = replace(original, detector_revision='source-' + 'c'*64,
                    step_id='d'*32, outcomes=('task_completed',), finding_observed=False)
    assert later.problem_key == original.problem_key
    assert 'この試行では観測せず' in document(later)[1]


def test_campaign_proposals_link_later_non_observation_and_missing_controls():
    from types import SimpleNamespace
    from hook_monitor.evaluation.flow_lab.agent import Action
    from hook_monitor.evaluation.flow_lab.proposal import proposals
    def observed(revision, outcomes, controls=True):
        return SimpleNamespace(
            actions=(Action('public', 'plain'),), causes=(None,),
            public_control=controls, protected_control=controls,
            spec=SimpleNamespace(detector_revision='source-' + revision*64, run_id=revision*32),
            observations=(SimpleNamespace(step_id=revision*32, outcomes=lambda: outcomes),),
        )
    items = proposals((observed('a', ('unnecessary_stop',)), observed('b', ('task_completed',))))
    assert len(items) == 2 and items[0].problem_key == items[1].problem_key
    assert items[0].finding_observed and not items[1].finding_observed
    unknown = proposals((observed('c', (), False),))
    assert len(unknown) == 1 and unknown[0].kind == 'incomplete_observation'
