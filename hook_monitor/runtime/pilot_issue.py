"""Build public proposals from closed classifications and counts, never raw text."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from hook_monitor.runtime.pilot_models import (
    CauseCategory, ProblemSymptom, ReasonCode, ReviewState, ToolFamily,
)

CAUSE_LABELS = {
    CauseCategory.EXTERNALITY: "外部への操作かどうかの判断",
    CauseCategory.PAYLOAD_RESOLUTION: "送信内容の確認",
    CauseCategory.PROTECTED_MATCH: "保護対象との照合",
    CauseCategory.LINEAGE: "情報のつながりの追跡",
    CauseCategory.COVERAGE_BOUNDARY: "観測できる範囲",
    CauseCategory.EXPLANATION: "停止理由の説明",
    CauseCategory.UNIDENTIFIED: "原因未特定",
}
FAMILY_LABELS = dict(zip(ToolFamily, ("端末操作", "外部連携", "関数操作", "組み込み検索等",
                                      "操作の継続", "その他"), strict=True))
SYMPTOM_LABELS = dict(zip(ProblemSymptom, ("不要な停止", "見逃し候補", "再現済みの見逃し",
                                          "判断不能", "観測不能", "評価記録漏れ"), strict=True))


def _count(value: object, *, unknown: bool = False) -> None:
    if unknown and value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000_000:
        raise ValueError("proposal count must be a bounded nonnegative integer")


@dataclass(frozen=True)
class PilotProposal:
    comparison_id: str
    detector_version: str
    kind: str
    cause: CauseCategory
    reason: ReasonCode
    tool_family: ToolFamily
    project_count: int
    operation_count: int
    stop_confirmation_count: int
    problem_count: int | None
    symptoms: dict[str, int]
    problem_project_count: int | None = None

    def __post_init__(self):
        if not isinstance(self.comparison_id, str) or not re.fullmatch(r"[0-9a-f]{64}", self.comparison_id):
            raise ValueError("invalid comparison reference")
        if not isinstance(self.detector_version, str) or not re.fullmatch(r"pilot-v1-[0-9a-f]{48}", self.detector_version):
            raise ValueError("only hashed runtime detector versions can be shared")
        if self.kind not in {"detection", "coverage", "recording_gap"}:
            raise ValueError("unknown proposal kind")
        for value, enum in ((self.cause, CauseCategory), (self.reason, ReasonCode), (self.tool_family, ToolFamily)):
            if not isinstance(value, enum):
                raise ValueError("proposal classifications must be closed enums")
        _count(self.project_count)
        _count(self.operation_count)
        _count(self.stop_confirmation_count)
        if self.stop_confirmation_count > self.operation_count:
            raise ValueError("stop confirmations cannot exceed comparison operations")
        _count(self.problem_count, unknown=True)
        _count(self.problem_project_count, unknown=True)
        if self.problem_project_count is not None and self.problem_project_count > self.project_count:
            raise ValueError("problem projects cannot exceed comparison projects")
        if not isinstance(self.symptoms, dict) or set(self.symptoms) != {str(item) for item in ProblemSymptom}:
            raise ValueError("proposal symptoms must use the complete closed set")
        for value in self.symptoms.values():
            _count(value)

    @property
    def problem_key(self) -> str:
        value = [self.detector_version, self.kind, self.cause, self.reason, self.tool_family]
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()

    @property
    def delivery_key(self) -> str:
        return hashlib.sha256(f"{self.comparison_id}:{self.problem_key}".encode()).hexdigest()


def parse_proposal(data: dict) -> PilotProposal:
    values = dict(data)
    for key, enum in (("cause", CauseCategory), ("reason", ReasonCode), ("tool_family", ToolFamily)):
        values[key] = enum(values[key])
    return PilotProposal(**values)


def proposal_document(item: PilotProposal) -> tuple[str, str]:
    item = parse_proposal(asdict(item))
    title = f"検出改善の提案: {CAUSE_LABELS[item.cause]} / {FAMILY_LABELS[item.tool_family]}"
    count = "不明" if item.problem_count is None else str(item.problem_count)
    lines = [f"<!-- tooluseproxy-problem:{item.problem_key} -->",
             f"<!-- tooluseproxy-delivery:{item.delivery_key} -->", "",
             "継続評価で見つかった問題の改善提案です。個別の記録やプロジェクト名は含みません。", "",
             f"- 判定方式: {item.detector_version}",
             f"- 対象プロジェクト数: {item.project_count}",
             f"- この問題を確認したプロジェクト数: {item.problem_project_count if item.problem_project_count is not None else '不明'}",
             f"- 比較対象の操作数: {item.operation_count}",
             f"- 停止確認済みの件数: {item.stop_confirmation_count}",
             f"- この問題の件数: {count}",
             f"- 原因分類: {CAUSE_LABELS[item.cause]}", f"- 理由番号: {item.reason.value}", ""]
    for symptom in ProblemSymptom:
        unknown_symptom = item.problem_count is None and (
            (item.kind == "coverage" and symptom == ProblemSymptom.NOT_VISIBLE)
            or (item.kind == "recording_gap" and symptom == ProblemSymptom.RECORD_FAILURE))
        lines.append(f"- {SYMPTOM_LABELS[symptom]}: {'不明' if unknown_symptom else item.symptoms[str(symptom)]}")
    lines.extend(["", "改善案: この分類の人工データによる再現例を追加し、判定条件と説明を点検する。",
                  "改善後は同じ分類の件数、不要な停止、再現済みの見逃し、判断時間を比べる。",
                  "通常利用の許可がすべて正しかったとは確認しておらず、全体の正解率や見逃し率は計算しない。",
                  "このIssueは提案のみで、コード変更・自動実験・設定変更を依頼するものではない。"])
    if item.kind != "detection":
        lines.append("観測範囲と記録の欠落に関する提案であり、判定の誤りが確認されたという意味ではない。")
    return title, "\n".join(lines)


def validate_document(item: PilotProposal, *, title: str, body: str) -> None:
    if (title, body) != proposal_document(item):
        raise ValueError("proposal text is not the approved content-free template")


def proposals_for_comparison(comparison_id: str, report: dict) -> tuple[PilotProposal, ...]:
    comparison = report["comparison"]
    review_counts = report["totals"]["review"]
    if set(review_counts) != {str(item) for item in ReviewState}:
        raise ValueError("comparison review counts must use the complete closed set")
    stop_confirmation_count = sum(
        review_counts[str(state)]
        for state in (
            ReviewState.CORRECT_BLOCK,
            ReviewState.UNNECESSARY_BLOCK,
            ReviewState.UNABLE_TO_JUDGE,
        )
    )
    common = dict(comparison_id=comparison_id, detector_version=comparison["detector_version"],
                  operation_count=comparison["observation_count"],
                  stop_confirmation_count=stop_confirmation_count,
                  project_count=comparison["project_count"])
    items = []
    for group in report["problem_groups"]:
        items.append(PilotProposal(**common, kind="detection", cause=CauseCategory(group["cause"]),
                     reason=ReasonCode(group["reason_code"]), tool_family=ToolFamily(group["tool_family"]),
                     problem_project_count=group["project_count"], problem_count=group["problem_count"],
                     symptoms=group["symptom"]))
    coverage = report["coverage"]
    unknown = coverage["unknown_task_count"] + coverage["projects_without_task_records"]
    for family in ToolFamily:
        count = coverage["unmatched_by_family"][str(family)]
        if count:
            symptoms = {str(item): 0 for item in ProblemSymptom}
            symptoms[str(ProblemSymptom.NOT_VISIBLE)] = count
            items.append(PilotProposal(**common, kind="coverage", cause=CauseCategory.COVERAGE_BOUNDARY,
                         reason=ReasonCode.TOOL_NOT_VISIBLE, tool_family=family,
                         problem_count=count, symptoms=symptoms))
    if unknown:
        symptoms = {str(item): 0 for item in ProblemSymptom}
        items.append(PilotProposal(**common, kind="coverage", cause=CauseCategory.COVERAGE_BOUNDARY,
                     reason=ReasonCode.UNMAPPED, tool_family=ToolFamily.OTHER,
                     problem_count=None, symptoms=symptoms))
    if report["limitations"]["recording_gap_count_unknown"]:
        items.append(PilotProposal(**common, kind="recording_gap", cause=CauseCategory.UNIDENTIFIED,
                     reason=ReasonCode.UNMAPPED, tool_family=ToolFamily.OTHER,
                     problem_count=None,
                     symptoms={str(item): 0 for item in ProblemSymptom}))
    return tuple(items)
