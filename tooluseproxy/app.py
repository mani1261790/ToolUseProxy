"""Product v2 command router. Legacy analysis is not a runtime dependency."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
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
    for name in ("setup", "init", "status", "doctor", "logs", "protect", "unsetup", "hook"):
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
                help="ToolCallのI/Oと登録メタデータをCodex判定モデルへ渡すことを確認",
            )
            command.add_argument("--model")
            command.add_argument("--no-viewer", action="store_true")
        if name == "logs":
            command.add_argument("--foreground", action="store_true")
        if name == "protect":
            command.add_argument("operation", choices=("plan", "add", "list"))
            command.add_argument("--path", type=Path)
        if name == "unsetup":
            command.add_argument("operation", choices=("plan", "apply"))
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
        "mode": "enforce",
        "failure_policy": "allow_with_warning",
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
    if not args.accept_judge_data:
        return {
            "status": "consent_required",
            "message": "ToolCallのI/OをCodexの判定モデルへ渡します。"
            "送信先と、判定不能時は警告して継続する方針を確認してから設定してください。",
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
        "failure_policy": "allow_with_warning",
        "hook_verified": False,
    }
    if not args.no_viewer:
        from tooluseproxy.viewer_process import start

        result["viewer"] = start(paths.db_path, root)
    return result, 0


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
        raise ValueError("source_path_required")
    path = (root / args.path).resolve(strict=True)
    relative = path.relative_to(root).as_posix()
    if not path.is_file():
        raise ValueError("source_must_be_file")
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
        raise ValueError("setup_required")
    with sqlite3.connect(paths.db_path, timeout=5) as conn:
        conn.execute(
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
    return {**result, "status": "registered"}, 0


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
        with workspace_authority_lease(paths.db_path, str(root)) as state:
            if state is not None and state.phase != "active":
                result, code = {"status": state.phase, "database_opened": False}, 1
            elif args.command in ("setup", "init"):
                result, code = _setup(args, paths, root)
            elif args.command == "protect":
                result, code = _protect(args, paths, root)
            elif args.command in ("status", "doctor"):
                from tooluseproxy.engine.workspace import make_workspace_id

                config = configuration(paths.db_path, make_workspace_id(str(root)))
                result, code = (
                    {
                        "engine": "semantic-flow-v2",
                        "configured": config is not None,
                        "hook_verified": False,
                        "failure_policy": "allow_with_warning",
                    },
                    0,
                )
            elif args.command == "unsetup":
                # No agent-facing writer to administrator lifecycle state.
                result, code = (
                    {
                        "status": "administrator_action_required",
                        "message": "保護解除は管理者側の承認経路から行います。設定は変更していません。",
                    },
                    1,
                )
            else:
                if args.foreground:
                    from tooluseproxy.log_viewer import serve_workspace

                    return serve_workspace(paths.db_path, root, as_json=args.json)
                from tooluseproxy.viewer_process import start

                result, code = start(paths.db_path, root), 0
        print(json.dumps(result, ensure_ascii=False))
        return code
    except Exception:
        # Errors can contain private paths or model context; use a value-free diagnostic.
        print(
            json.dumps(
                {
                    "status": "operation_unavailable",
                    "message": "操作を完了できませんでした。"
                    "旧版のコマンドや設定は自動適用しません。",
                },
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
