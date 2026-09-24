"""Product v2 command router. Legacy analysis is not a runtime dependency."""

from __future__ import annotations

import argparse
import errno
import json
import os
import sqlite3
import tempfile
import shlex
import subprocess
import sys
from pathlib import Path

from tooluseproxy import __version__
from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.journal import Journal
from tooluseproxy.engine.runtime import configuration
from tooluseproxy.integrations.authority import workspace_authority_lease
from tooluseproxy.paths import (
    prepare_data_directory,
    resolve_runtime_paths,
    secure_database_permissions,
)


def parser():
    result = argparse.ArgumentParser(
        description="ToolUseProxy: ToolCallの意味依存グラフによる送信判定"
    )
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("setup", "init", "status", "doctor", "logs", "protect", "unsetup", "analyze", "hook"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", type=Path)
        command.add_argument("--db", type=Path)
        command.add_argument("--json", action="store_true")
        if name == "hook":
            command.add_argument(
                "phase",
                choices=(
                    "session-start",
                    "subagent-start",
                    "pre-tool-use",
                    "post-tool-use",
                    "stop",
                ),
            )
            continue
        command.add_argument("--workspace", type=Path, required=True)
        if name in ("setup", "init"):
            command.add_argument(
                "--accept-judge-data",
                action="store_true",
                help="ToolCallのI/O・必要な資源の証拠を判定モデルへ渡し、バックグラウンドで来歴を解析することを確認",
            )
            command.add_argument("--model")
            command.add_argument("--no-viewer", action="store_true")
            command.add_argument("--protect", type=Path, action="append", default=[])
        if name == "analyze":
            command.add_argument("operation", choices=("status", "run"))
        if name == "logs":
            command.add_argument("--foreground", action="store_true")
        if name == "protect":
            command.add_argument("operation", choices=("plan", "add", "list"))
            command.add_argument("--path", type=Path)
        if name == "unsetup":
            command.add_argument("operation", choices=("plan", "apply", "open"))
    return result


def save_configuration(db: Path, workspace: str, model):
    from tooluseproxy.engine.runtime import session_lock

    with session_lock(db, "configuration", "all"):
        return _save_configuration(db, workspace, model)


def _save_configuration(db: Path, workspace: str, model):
    # Setup is the only writer; judge responses cannot change this configuration.
    path = db.parent / "semantic-flow.json"
    if path.exists():
        if path.is_symlink():
            raise ValueError("configuration_symlink")
        value = json.loads(path.read_text())
    else:
        value = {"workspaces": {}}
    existing = value["workspaces"].get(workspace)
    config = {
        "provider": "codex_exec",
        "model": model,
        "send_recorded_content": True,
        "background_provenance": True,
        "mode": "enforce",
        "failure_policy": "wait_for_decision",
    }
    if existing is not None and existing != config:
        raise ValueError("existing_judge_configuration_differs")
    value["workspaces"][workspace] = config
    descriptor, temporary = tempfile.mkstemp(dir=db.parent, prefix=".semantic-config-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(value, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _setup(args, paths, root):
    from tooluseproxy.engine.workspace import make_workspace_id

    existing = configuration(paths.db_path, make_workspace_id(str(root)))
    if existing is not None:
        if args.model is not None and args.model != existing.get("model"):
            return {
                "status": "judge_configuration_differs",
                "message": "設定済みの判定モデルと異なります。設定は変更していません。",
            }, 1
        result = {
            "status": "already_configured",
            "engine": "semantic-flow-v2",
            "workspace_root": str(root),
            "model": existing.get("model"),
            "hook_verified": False,
            "message": "初期設定済みです。",
        }
        return _finish_setup(args, paths, root, result)
    if not args.accept_judge_data:
        return {
            "status": "consent_required",
            "message": "ToolCallのI/Oと必要なローカル資源の証拠をCodexの判定モデルへ渡します。バックグラウンド解析もモデルを使用します。"
            "送信先と、判定中は実行を保留する方針を確認してから設定してください。",
        }, 1
    if not paths.db_path.exists() and (root / "protected_sources.json").exists():
        return {
            "status": "legacy_registration_review_required",
            "message": "既存の保護登録ファイルがあります。内容は開いていません。移行対象を確認してください。",
        }, 1
    prepare_data_directory(paths)
    journal = Journal(paths.db_path)
    journal.initialize()
    workspace = journal.register_workspace(str(root))
    save_configuration(paths.db_path, workspace.workspace_id, args.model)
    from tooluseproxy.integrations.activation import save_workspace_activations

    save_workspace_activations(paths.db_path, str(root))
    secure_database_permissions(paths.db_path)
    result = {
        "status": "configured_unverified",
        "engine": "semantic-flow-v2",
        "workspace_id": workspace.workspace_id,
        "workspace_root": str(root),
        "db_path": str(paths.db_path),
        "judge": "codex_exec",
        "model": args.model,
        "failure_policy": "wait_for_decision",
        "hook_verified": False,
    }
    return _finish_setup(args, paths, root, result)


def _finish_setup(args, paths, root, result):
    from argparse import Namespace
    with sqlite3.connect(paths.db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS recording_boundaries (workspace_id TEXT PRIMARY KEY, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, after_sequence INTEGER NOT NULL)")
        from tooluseproxy.engine.workspace import make_workspace_id
        workspace = make_workspace_id(str(root))
        conn.execute("INSERT OR IGNORE INTO recording_boundaries(workspace_id,after_sequence) VALUES (?, (SELECT COALESCE(MAX(sequence_no),0) FROM events))", (workspace,))
        started, sequence = conn.execute("SELECT started_at,after_sequence FROM recording_boundaries WHERE workspace_id=?", (workspace,)).fetchone()
    result["recording"] = {"started_at": started, "after_sequence": sequence, "history_imported": False}
    result["unsetup"] = {"command": "unsetup open", "message": "導入をやめる場合は「ToolUseProxyを解除したい」と伝えてください。管理者の認証・確認画面へ案内します。"}
    result["registrations"] = []
    code = 0
    for path in args.protect:
        registration, outcome = _protect(Namespace(operation="add", path=path), paths, root)
        result["registrations"].append(registration)
        code = max(code, outcome)
    if not args.no_viewer:
        from tooluseproxy.viewer_process import start
        result["viewer"] = start(paths.db_path, root)
    return result, code


def _unsetup(args, paths, root):
    from tooluseproxy.authority_admin import ADMIN_SCRIPT
    result = {"status": "administrator_action_required", "message": "解除には管理者の認証と対象確認が必要です。設定・登録・ログは保持します。", "changed": False}
    if args.operation != "open":
        return result, 1
    if sys.platform != "darwin" or not ADMIN_SCRIPT.is_file():
        return {**result, "status": "administrator_installation_required", "message": "管理者用解除ツールが未導入です。管理者による初回導入が必要です。"}, 1
    # Refuse before elevation if any component can be replaced by this user.
    for entry in (ADMIN_SCRIPT, *ADMIN_SCRIPT.parents):
        metadata = entry.lstat()
        if entry.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return {**result, "status": "administrator_installation_invalid"}, 1
    if ADMIN_SCRIPT.stat().st_mode & 0o222:
        return {**result, "status": "administrator_installation_invalid"}, 1
    # OS authorization runs only the fixed administrator-owned entrypoint. No
    # user-provided executable, script, or shell fragments are accepted.
    command = shlex.join(["/usr/bin/python3", "-I", "-S", str(ADMIN_SCRIPT), "deactivate", "--gui", "--uid", str(os.getuid()), "--workspace", str(root), "--data-dir", str(paths.data_dir)])
    script = "do shell script " + json.dumps(command, ensure_ascii=False) + " with administrator privileges"
    try:
        response = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {**result, "status": "administrator_result_unknown", "message": "管理者操作の結果を取得できませんでした。状態を確認してください。"}, 1
    # The administrator process performs every validation and the actual change.
    if response.returncode:
        return {**result, "status": "administrator_not_completed", "message": "解除は完了していません。キャンセルまたは管理者側の確認に失敗しました。"}, 1
    return {"status": "administrator_completed", "message": response.stdout.strip()}, 0


def _protect(args, paths, root):
    from tooluseproxy.engine.workspace import make_workspace_id

    workspace = make_workspace_id(str(root))
    journal = Journal(paths.db_path)
    if args.operation == "list":
        sources = journal.list_protected_sources_for_workspace(workspace)
        return {
            "sources": [
                {"id": source.source_id, "path": source.path, "selector": source.selector}
                for source in sources
            ]
        }, 0
    if args.path is None:
        return {"status": "source_path_required", "message": "登録するファイルを指定してください。"}, 1
    try:
        path = (root / args.path).resolve(strict=True)
    except FileNotFoundError:
        return {"status": "source_not_found", "message": "指定したファイルが見つかりません。"}, 1
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return {"status": "source_outside_workspace", "message": "このプロジェクト内のファイルを指定してください。"}, 1
    if not path.is_file():
        return {"status": "source_must_be_file", "message": "登録対象はファイル単位です。ファイルを指定してください。"}, 1
    result = {
        "workspace": str(root),
        "path": relative,
        "scope": "whole_file",
        "content_read": False,
        "source_id": "src:" + digest([workspace, relative]),
    }
    if args.operation == "plan":
        return result, 0
    if configuration(paths.db_path, workspace) is None:
        return {"status": "setup_required", "message": "このプロジェクトは未初期化です。先に初期設定が必要です。"}, 1
    with sqlite3.connect(paths.db_path, timeout=5) as conn:
        inserted = conn.execute(
            "INSERT OR IGNORE INTO protected_sources "
            "(source_id,path,source_type,sensitivity,policy_tags_json,selector_json,workspace_id,source_key) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                result["source_id"],
                relative,
                "file",
                "secret",
                "[]",
                json.dumps({"kind": "whole_file", "values": []}),
                workspace,
                relative,
            ),
        )
        registered = inserted.rowcount == 1
    return {
        **result,
        "status": "registered" if registered else "already_registered",
        "message": "ファイル全体を保護対象に登録しました。" if registered else "このファイルは登録済みです。",
    }, 0


def administrator_status():
    from tooluseproxy.authority_admin import ADMIN_SCRIPT
    try:
        for entry in (ADMIN_SCRIPT, *ADMIN_SCRIPT.parents):
            info = entry.lstat()
            if entry.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                return "invalid_installation"
        return "installed_authentication_unverified" if not ADMIN_SCRIPT.stat().st_mode & 0o222 else "invalid_installation"
    except OSError:
        return "not_installed"


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        paths = resolve_runtime_paths(db_path=args.db, data_dir=args.data_dir)
        if args.command == "hook":
            from tooluseproxy.engine.hook import run

            return run(args.phase, paths.db_path)
        root = args.workspace.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace_must_be_directory")
        if args.command == "unsetup":
            result, code = _unsetup(args, paths, root)
            print(json.dumps(result, ensure_ascii=False))
            return code
        with workspace_authority_lease(paths.db_path, str(root)) as state:
            if state is not None and state.phase != "active":
                result, code = {"status": state.phase, "database_opened": False}, 1
            elif args.command in ("setup", "init"):
                result, code = _setup(args, paths, root)
            elif args.command == "protect":
                result, code = _protect(args, paths, root)
            elif args.command == "analyze":
                from tooluseproxy.engine.workspace import make_workspace_id
                from tooluseproxy.engine.jobs import drain, queue_status
                scope = make_workspace_id(str(root))
                from tooluseproxy.engine.pending import resume, status as pending_status
                resumed = resume(paths.db_path, scope) if args.operation == "run" else 0
                count = drain(paths.db_path, scope) if args.operation == "run" else 0
                result, code = {"completed": count, "queue": queue_status(paths.db_path, scope),
                                "judgments_completed": resumed, "judgments": pending_status(paths.db_path, scope),
                                "tools_executed": False}, 0
            elif args.command in ("status", "doctor"):
                from tooluseproxy.engine.workspace import make_workspace_id

                from tooluseproxy.engine.jobs import queue_status
                config = configuration(paths.db_path, make_workspace_id(str(root)))
                result, code = (
                    {
                        "engine": "semantic-flow-v2",
                        "configured": config is not None,
                        "background_provenance": bool(config and config.get("background_provenance")),
                        "queue": queue_status(paths.db_path, make_workspace_id(str(root))),
                        "administrator": administrator_status(),
                        "hook_verified": False,
                        "failure_policy": "wait_for_decision",
                    },
                    0,
                )
            elif args.command == "unsetup":
                result, code = _unsetup(args, paths, root)
            else:
                if args.foreground:
                    from tooluseproxy.log_viewer import serve_workspace

                    return serve_workspace(paths.db_path, root, as_json=args.json)
                from tooluseproxy.viewer_process import start

                result, code = start(paths.db_path, root), 0
        print(json.dumps(result, ensure_ascii=False))
        return code
    except Exception as error:
        # Exception text may contain private paths or content. Classify only
        # stable OS/SQLite codes, without hiding permission failures as generic
        # product errors or granting permissions ourselves.
        sqlite_code = getattr(error, "sqlite_errorcode", None)
        readonly = (isinstance(error, sqlite3.Error) and isinstance(sqlite_code, int)
                    and sqlite_code & 0xff == sqlite3.SQLITE_READONLY)
        permission = (isinstance(error, PermissionError) or
                      isinstance(error, OSError) and error.errno in (errno.EACCES, errno.EPERM))
        result = {
            "status": "operation_unavailable",
            "message": "操作を完了できませんでした。旧版のコマンドや設定は自動適用しません。",
        }
        if permission or readonly:
            result = {
                "status": "filesystem_access_required",
                "reason": "database_readonly" if readonly else "permission_denied",
                "message": "ファイルへのアクセス権限が不足しているか、データベースが読取り専用です。"
                "Codexの通常の権限申請で必要な範囲だけ確認し、許可後に同じ操作を再実行してください。"
                "申請機能が使えない場合は、その状態を報告してください。",
            }
        print(json.dumps(result, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
