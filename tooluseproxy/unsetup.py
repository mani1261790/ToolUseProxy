"""Read-only Unsetup preview; no authority to disable protection lives here."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from hook_monitor.runtime.workspace import resolve_workspace


def plan_unsetup(workspace: Path, database: Path) -> dict[str, Any]:
    context = resolve_workspace(str(workspace), str(workspace))
    if not context.ready:
        raise ValueError(f"workspace is not usable: {context.status}")
    # Deliberately do not open the database, activation files or source manifest.
    # A preview must remain available during DB failure and is not an approval
    # capability or evidence that the workspace is currently protected.
    return {
        "schema_version": 1,
        "status": "preview_only",
        "action": "unsetup",
        "workspace_root": context.canonical_root,
        "workspace_id": context.workspace_id,
        "database": str(database),
        "activation_state": "not_inspected",
        "apply_available": False,
        "approval_status": "trusted_approval_channel_unavailable",
        "database_opened": False,
        "source_manifest_opened": False,
        "changes_applied": False,
        "message": "解除の扱いを表示しました。保護は変更していません。",
        "proposed_effects": [
            "指定プロジェクトの監視を停止し、未初期化として扱う。",
            "設定・保護対象登録・履歴を保持する。履歴削除は別の操作とする。",
            "元ファイル・利用者管理の保護リスト・他プロジェクトを変更しない。",
            "再初期化時は過去の登録と設定が残っていることを表示し、利用者が確認する。",
        ],
        "limitations": [
            "現在の有効状態と登録件数は未調査。適用前に管理側で再確認する。",
            "このCLIには承認権限がない。独立した管理者用入口の導入と人間の操作が必要。",
            "確認番号・会話・環境変数・端末入力を人間の承認とは扱わない。",
        ],
    }


def unavailable_unsetup_application() -> dict[str, Any]:
    # No caller-controlled token, environment flag, TTY or callback may turn
    # this into an authorized mutation. A separate authority is required.
    return {
        "schema_version": 1,
        "status": "denied",
        "code": "trusted_approval_channel_unavailable",
        "changes_applied": False,
        "message": "このCLIでは利用者承認を受け付けないため、解除しません。",
        "recovery": "導入済みの独立した管理者用入口で、人間が対象projectの停止を行ってください。未導入時の故障復旧は、利用者がCodexのPlugin管理画面で手動で無効化してください。"
                    "これは全プロジェクトに影響し、プロジェクト単位のUnsetupとは異なります。",
    }
