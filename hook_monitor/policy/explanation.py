from __future__ import annotations

import shlex
from pathlib import Path

from hook_monitor.policy.models import PolicyDecision, PolicyExplanation


def build_policy_explanation(
    decision: PolicyDecision,
    *,
    db_path: Path | None = None,
    analysis_run_id: str | None = None,
) -> PolicyExplanation:
    source_label = f"{decision.source_node_kind}:{decision.source_node_id}"
    sink_label = f"sink_candidate:{decision.sink_node_id}"
    trace_command = _trace_command(decision, db_path, analysis_run_id)
    return PolicyExplanation(
        decision_id=decision.decision_id,
        finding_id=decision.finding_id,
        action=decision.action,
        severity=decision.severity,
        hook_event=decision.hook_event,
        source_label=source_label,
        sink_label=sink_label,
        sink_type=decision.sink_type,
        path_score=decision.path_score,
        user_message=_user_message(decision),
        technical_summary=(
            f"source={source_label} sink={decision.sink_type} "
            f"score={decision.path_score:.2f} severity={decision.severity}"
        ),
        trace_command=trace_command,
        path_summary=(source_label, decision.sink_type),
    )


def render_hook_message(explanation: PolicyExplanation) -> str:
    return "\n".join(
        (
            explanation.user_message,
            _result_message(explanation),
            (
                "技術情報（通常は読む必要なし）｜"
                f"送信先：{explanation.sink_type}｜"
                f"判定：{explanation.action}｜"
                f"調査用：{explanation.trace_command}"
            ),
        )
    )


def _user_message(decision: PolicyDecision) -> str:
    if decision.evidence_kind == "unresolved_external_payload":
        return (
            "ToolUseProxyが外部送信を実行前に止めました。送信内容を安全に"
            "確認しきれなかったため、保護対象が含まれていないとは判断"
            "できませんでした。送信する内容やcommandを単純にしてから"
            "やり直してください。"
        )
    if decision.evidence_kind == "resolved_file_exact":
        return (
            "ToolUseProxyが外部送信を実行前に止めました。参照ファイルに"
            "保護対象の内容が含まれています。保護対象を除くか、公開用の"
            "ファイルを選んでからやり直してください。"
        )
    if decision.sink_type == "final_answer":
        return (
            "最終回答に保護対象の内容が含まれています。ToolUseProxyが回答を"
            "止めたため、保護対象を除いてから回答を作り直してください。"
        )
    if decision.sink_type.startswith("external_"):
        return (
            "外部へ送る内容に保護対象が含まれています。送信内容から"
            "保護対象を除いてからやり直してください。"
        )
    return (
        "保護対象の内容が制限対象の操作に含まれています。操作内容から"
        "保護対象を除いてからやり直してください。"
    )


def _result_message(explanation: PolicyExplanation) -> str:
    if (
        explanation.sink_type == "final_answer"
        and explanation.action == "continue_review"
    ):
        return "結果：この回答はまだ利用者へ返していません。保護対象の内容も表示していません。"
    if (
        explanation.action == "block"
        and explanation.hook_event in {"PreToolUse", "PermissionRequest"}
    ):
        return "結果：外部操作は実行されていません。保護対象の内容も表示していません。"
    if explanation.hook_event == "PostToolUse":
        return "結果：この確認は操作後です。実行済みの操作は取り消せません。保護対象の内容は表示していません。"
    return "結果：保護対象の内容は表示していません。操作を続ける前に送信内容を確認してください。"


def _trace_command(
    decision: PolicyDecision,
    db_path: Path | None,
    analysis_run_id: str | None,
) -> str:
    parts = ["tooluseproxy", "trace"]
    if db_path is not None:
        parts.extend(("--db", str(db_path)))
    if analysis_run_id is not None:
        parts.extend(("--analysis-run", analysis_run_id))
    parts.extend(("--node", f"sink_candidate:{decision.sink_node_id}"))
    return shlex.join(parts)
