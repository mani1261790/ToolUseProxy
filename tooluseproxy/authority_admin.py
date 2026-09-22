"""Human-operated administrator entry point, built as an isolated single file.

The prompt is not authentication. OS administrator execution, immutable code
and a deployment that denies the agent administrator access are prerequisites.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import os
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from tooluseproxy.authority_state import (  # standalone-build: remove-import
    AUTHORITY_DIRECTORY, AuthorityError, State, Target, _Store,
)

ADMIN_DIRECTORY = Path("/Library/Application Support/ToolUseProxy/Admin")
ADMIN_SCRIPT = ADMIN_DIRECTORY / "authority-admin.py"
REVIEW_SECONDS = 120.0


@dataclass(frozen=True)
class _Review:
    target: Target
    action: str
    expected: str
    operation: str
    workspace_identity: tuple[int, int]
    data_identity: tuple[int, int]
    started: float


def _directory_identity(value: str, uid: int) -> tuple[str, tuple[int, int]]:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise AuthorityError("administrator_target_requires_absolute_directory")
    canonical = path.resolve(strict=True)
    descriptor = os.open(canonical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
            raise AuthorityError("administrator_target_owner_mismatch")
        return str(canonical), (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)


def _require_administrator_installation() -> None:
    if os.geteuid() != 0:
        raise AuthorityError("administrator_context_required")
    if sys.platform != "darwin":
        raise AuthorityError("administrator_platform_unsupported")
    if not sys.flags.isolated or not sys.flags.no_site:
        raise AuthorityError("administrator_requires_isolated_python")
    if Path(__file__) != ADMIN_SCRIPT:
        raise AuthorityError("administrator_requires_installed_entrypoint")
    with _Store(ADMIN_DIRECTORY).opened() as directory:
        descriptor = _Store(ADMIN_DIRECTORY)._open_file(directory, ADMIN_SCRIPT.name)
        try:
            if os.fstat(descriptor).st_mode & 0o222:
                raise AuthorityError("administrator_code_is_writable")
        finally:
            os.close(descriptor)
    interpreter = Path(sys.executable).resolve(strict=True)
    with _Store(interpreter.parent).opened() as directory:
        descriptor = _Store(interpreter.parent)._open_file(directory, interpreter.name)
        os.close(descriptor)


def _review(store: _Store, *, uid: int, workspace: str, data_dir: str,
            action: str) -> _Review:
    if action not in ("enroll", "deactivate", "reactivate", "finish"):
        raise AuthorityError("invalid_authority_action")
    workspace, workspace_identity = _directory_identity(workspace, uid)
    data_dir, data_identity = _directory_identity(data_dir, uid)
    target = Target(uid, workspace, data_dir)
    with store.opened() as directory:
        current = store.read(directory, target)
    if action == "enroll" and current is not None:
        raise AuthorityError("authority_already_enrolled")
    if action != "enroll" and current is None:
        raise AuthorityError("authority_enrollment_required")
    if action == "finish" and (current is None or current.phase != "deactivating"):
        raise AuthorityError("authority_not_deactivating")
    if action == "reactivate" and current is not None and current.phase != "inactive":
        raise AuthorityError("authority_not_inactive")
    if action == "deactivate" and current is not None and current.phase != "active":
        raise AuthorityError("authority_not_active")
    return _Review(target, action, current.generation if current else "absent",
                   current.operation if action == "finish" else uuid.uuid4().hex,
                   workspace_identity, data_identity, time.monotonic())


def _apply_review(store: _Store, review: _Review, answer: str) -> State:
    # Confirmation is UX only. transition() independently checks OS identity.
    if answer != "確認して適用":
        raise AuthorityError("administrator_cancelled")
    # Compare to the deadline itself: subtracting two float clock readings can
    # round an exact 120-second deadline down to 119.99999999999999.
    if not review.started <= time.monotonic() < review.started + REVIEW_SECONDS:
        raise AuthorityError("administrator_review_expired")
    workspace, workspace_identity = _directory_identity(review.target.workspace, review.target.uid)
    data_dir, data_identity = _directory_identity(review.target.data_dir, review.target.uid)
    if (workspace != review.target.workspace or data_dir != review.target.data_dir
            or workspace_identity != review.workspace_identity
            or data_identity != review.data_identity):
        raise AuthorityError("administrator_target_changed")
    return store.transition(review.target, expected=review.expected, operation=review.operation,
                            action="deactivate" if review.action == "finish" else review.action)


def _render_review(review: _Review) -> None:
    labels = {"enroll": "管理側への初期登録", "deactivate": "このプロジェクトの利用停止",
              "reactivate": "このプロジェクトの再初期化", "finish": "実行中処理の終了確認"}
    print(f"操作: {labels[review.action]}")
    print(f"利用者UID: {review.target.uid}")
    # repr prevents a path with terminal control characters from spoofing the
    # confirmation display; the full canonical path remains visible.
    print(f"対象プロジェクト: {review.target.workspace!r}")
    print(f"専用データ領域: {review.target.data_dir!r}")
    print("設定・保護対象登録・履歴・元ファイルは保持します。保護リストを読みません。")
    print("他プロジェクトとPlugin全体の有効状態は変更しません。")
    if review.action == "enroll":
        print("初期登録は旧Hook・workerを終了し、Pluginを無効にした状態で行ってください。")
        print("登録後は、この管理側に対応した導入版で新しいタスクを開始してください。")
    if review.action == "reactivate":
        print("以前の設定・登録を引き継いで監視を再開します。空の設定には戻りません。")
    if review.action == "deactivate":
        print("実行中の処理がある間は停止処理中となります。新規Hookは受け付けません。")
    print("この入力はOS認証の代わりではありません。確認は120秒以内に行ってください。")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ToolUseProxy 管理者による利用停止・再初期化",
                                     allow_abbrev=False)
    parser.add_argument("action", choices=("status", "enroll", "deactivate", "reactivate", "finish"))
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--gui", action="store_true")
    args = parser.parse_args(argv)
    try:
        _require_administrator_installation()
        store = _Store(AUTHORITY_DIRECTORY)
        if args.action == "status":
            workspace, _ = _directory_identity(args.workspace, args.uid)
            data_dir, _ = _directory_identity(args.data_dir, args.uid)
            target = Target(args.uid, workspace, data_dir)
            with store.opened() as directory:
                state = store.read(directory, target)
            print(json.dumps(state.payload() if state else {"status": "not_enrolled"},
                             ensure_ascii=False, sort_keys=True))
            return 0
        if not args.gui and (not sys.stdin.isatty() or not sys.stdout.isatty()):
            raise AuthorityError("administrator_interactive_terminal_required")
        review = _review(store, uid=args.uid, workspace=args.workspace, data_dir=args.data_dir,
                         action=args.action)
        if args.gui:
            # This dialog is confirmation, not the authentication boundary.
            # _require_administrator_installation already checked root and code ownership.
            message = f"対象プロジェクト: {review.target.workspace!r}\n操作: {review.action}\n設定・保護登録・ログは保持します。"
            script = "display dialog " + json.dumps(message, ensure_ascii=False) + ' with title "ToolUseProxy" buttons {"キャンセル", "確認して適用"} default button "キャンセル" cancel button "キャンセル"'
            response = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, timeout=120)
            if response.returncode:
                raise AuthorityError("administrator_cancelled")
            answer = "確認して適用"
        else:
            _render_review(review)
            answer = input("続行する場合だけ「確認して適用」と入力: ")
        result = _apply_review(store, review, answer)
        messages = {"active": "利用可能です。保持中の設定・登録を引き継ぎます。",
                    "deactivating": "停止処理中です。実行中処理の終了後にfinishで確認してください。",
                    "inactive": "利用を停止しました。設定・登録・履歴は保持されています。"}
        print(messages[result.phase])
        return 0
    except (AuthorityError, OSError, EOFError, subprocess.TimeoutExpired) as error:
        code = str(error) if isinstance(error, AuthorityError) else "administrator_operation_failed"
        print(f"操作を完了できませんでした: {code}", file=sys.stderr)
        print("途中終了の場合はstatusで状態を確認してください。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
