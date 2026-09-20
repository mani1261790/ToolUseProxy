"""Closed synthetic issue documents: no commands, payloads, reasons or local paths."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re

from .agent import Action, Proposal as ActionProposal
from .findings import FAILURES, ReplayResult
from .models import canonical
from .preflight import LabError

KINDS = {*FAILURES, 'incomplete_observation', 'not_tested'}
LABELS = {
    'denial_delivery_conflict': '拒否後の到達',
    'protected_delivery_after_allow': '許可後の保護情報到達',
    'unnecessary_stop': '正常操作の停止',
    'hook_gap': 'Hook到達の欠落',
    'incomplete_observation': '観測不足',
    'not_tested': '未試行',
}
OUTCOMES = KINDS | {'protected_delivery', 'environment_denial', 'operation_not_started', 'task_completed'}


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def checked_hex(value, size=64):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{' + str(size) + '}', value):
        raise LabError('invalid_synthetic_proposal')


@dataclass(frozen=True)
class IssueProposal:
    kind: str
    action: dict
    detector_revision: str
    run_id: str
    step_id: str
    cause_digest: str | None
    outcomes: tuple[str, ...]
    finding_observed: bool
    controls_passed: bool
    schema: int = 1
    pending: bool = False

    def __post_init__(self):
        if type(self.schema) is not int or self.schema != 1 or self.kind not in KINDS:
            raise LabError('invalid_synthetic_proposal')
        parsed = ActionProposal.parse({'status': 'propose', 'actions': [self.action]})
        if self.action != asdict(parsed.actions[0]):
            raise LabError('invalid_synthetic_proposal')
        if not isinstance(self.detector_revision, str) or not self.detector_revision.startswith('source-'):
            raise LabError('invalid_synthetic_proposal')
        checked_hex(self.detector_revision[7:])
        checked_hex(self.run_id, 32)
        checked_hex(self.step_id, 32)
        if self.cause_digest is not None:
            checked_hex(self.cause_digest)
        if (not isinstance(self.outcomes, tuple) or len(self.outcomes) > len(OUTCOMES)
                or any(value not in OUTCOMES for value in self.outcomes)
                or len(set(self.outcomes)) != len(self.outcomes)
                or type(self.finding_observed) is not bool or type(self.controls_passed) is not bool
                or type(self.pending) is not bool):
            raise LabError('invalid_synthetic_proposal')

        expected = self.kind in self.outcomes or (
            self.kind == 'incomplete_observation' and not self.controls_passed)
        if self.finding_observed != expected:
            raise LabError('contradictory_synthetic_proposal')

    @property
    def problem_key(self):
        return digest({'schema': 1, 'kind': self.kind, 'action': self.action})

    @property
    def delivery_key(self):
        return digest(asdict(self))


def parse_proposal(value):
    fields = set(IssueProposal.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != fields or not isinstance(value['outcomes'], list):
        raise LabError('invalid_synthetic_proposal')
    try:
        return IssueProposal(**{**value, 'outcomes': tuple(value['outcomes'])})
    except (TypeError, ValueError):
        raise LabError('invalid_synthetic_proposal') from None


def proposals(results: tuple[ReplayResult, ...]):
    known = {}
    for result in results:
        for action, observation in zip(result.actions, result.observations):
            kinds = set(observation.outcomes()) & KINDS
            if not result.public_control or not result.protected_control:
                kinds.add('incomplete_observation')
            known.setdefault(canonical(asdict(action)), set()).update(kinds)
    items = {}
    for result in results:
        controls = result.public_control and result.protected_control
        for action, observation, cause in zip(result.actions, result.observations, result.causes):
            for kind in sorted(known[canonical(asdict(action))]):
                item = IssueProposal(kind, asdict(action), result.spec.detector_revision,
                                     result.spec.run_id, observation.step_id, cause,
                                     observation.outcomes(), kind in observation.outcomes() or (
                                         kind == 'incomplete_observation' and not controls), controls)
                items[item.delivery_key] = item
    return tuple(items.values())


def document(item: IssueProposal):
    # Revalidate even if a caller mutated the action dictionary after construction.
    item = parse_proposal({**asdict(item), 'outcomes': list(item.outcomes)})
    title = f'[人工試験] {LABELS[item.kind]} ({item.problem_key[:12]})'
    action = Action(**item.action)
    body = '\n'.join([
        f'<!-- tooluseproxy-lab-problem:{item.problem_key} -->',
        f'<!-- tooluseproxy-lab-delivery:{item.delivery_key} -->',
        '人工情報だけを使ったHTTP試験の観測です。実利用の結果とは区別します。', '',
        f'問題: {LABELS[item.kind]}',
        f'今回の観測: {"該当する観測あり" if item.finding_observed else "この試行では観測せず（修正の証明ではありません）"}',
        f'受信対照: {"確認済み" if item.controls_passed else "不足"}',
        f'原因の特定: {"判定根拠の指紋あり" if item.cause_digest else "未特定"}',
        f'操作: {action.source} / {action.encoding} / {action.representation} / {action.client}',
        f'検出器: {item.detector_revision}',
        f'観測参照: {item.run_id} / {item.step_id}',
        '試験状態: ' + ('未確定の予約。操作の成否は不明です。' if item.pending else '保存された試験結果'),
        f'判定根拠の指紋: {item.cause_digest or "未取得"}',
        f'観測分類: {", ".join(item.outcomes) or "該当なし"}', '',
        'コマンド本文・送受信本文・判定理由の自由文・ローカルパスは共有していません。',
        'native Codex Hookの到達や本番環境での修正完了は、この試験では証明しません。',
    ])
    return title, body
