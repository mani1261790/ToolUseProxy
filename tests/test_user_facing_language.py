from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_quickstart_presents_examples_without_requiring_fixed_phrases() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    quickstart = (REPO_ROOT / "QUICKSTART.md").read_text(encoding="utf-8")

    for document in (readme, quickstart):
        assert "ToolUseProxyをこのプロジェクトで使えるようにして" in document
        assert "守った方がよいファイルを探して" in document
        assert "この通りの言い方でなくても構いません" in document
        assert "固定フレーズではありません" in document
        assert "ToolUseProxy setup skillを使って" not in document
        assert "approve、reject、ignore" not in document


def test_setup_skill_keeps_implementation_words_out_of_user_choices() -> None:
    skill = (
        REPO_ROOT / "skills" / "tooluseproxy-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert (
        "ToolUseProxyの操作確認｜行うこと：...｜変更されるもの：...｜"
        "外部通信：...｜確認が必要な理由：...｜この内容で実行してよいですか？"
    ) in skill
    assert "このファイルをToolUseProxyで守りますか？" in skill
    assert "`守る` / `今回は見送る` / `今後は候補に出さない`" in skill
    assert "Never require the user to" in skill
    assert "reply with the English command words" in skill
    assert "Never require or compare against" in skill
    assert "not trigger strings" in skill
    assert "Never ask the user to repeat one of the examples verbatim" in skill


def test_normal_onboarding_does_not_require_internal_path_diagnostics() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    quickstart = (REPO_ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
    plugin_guide = (
        REPO_ROOT / "docs" / "設定" / "Plugin導入.md"
    ).read_text(encoding="utf-8")
    skill = (
        REPO_ROOT / "skills" / "tooluseproxy-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert "--expect-empty-settings" in skill
    assert "--whole-file" in skill
    assert "do not ask the user to paste `database_missing`" in skill
    assert "do not depend on a Hook diagnostic" in skill
    assert "If `PLUGIN_DATA` is not available" not in skill
    assert skill.count("--data-dir <PLUGIN_DATA>") == 2
    assert "Plugin is installed but this workspace is not\nprotected yet" in skill
    assert "1件ずつ確認" in readme
    assert "コピーして貼り直す必要はありません" in quickstart
    assert "ToolUseProxyが外部送信を実行前に止めました" in quickstart
    assert "結果：外部操作は実行されていません" in quickstart
    assert "貼り直しを要求しません" in plugin_guide
    assert "利用者が`doctor`、`status`、`init`、`PLUGIN_DATA`を組み立てる必要はありません" in plugin_guide
    assert "通常利用者がpathやcommandをコピーするための手順ではありません" in plugin_guide


def test_normal_onboarding_continues_when_selected_permissions_already_allow_plugin_data() -> None:
    skill = (
        REPO_ROOT / "skills" / "tooluseproxy-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")
    plugin_guide = (
        REPO_ROOT / "docs" / "設定" / "Plugin導入.md"
    ).read_text(encoding="utf-8")

    assert "per-command approval is disabled" in skill
    assert "already grants access to the installed Plugin data directory" in skill
    assert "must not make the user copy an internal command" in skill
    assert "run the exact setup\ncommand with the permissions already selected" in skill
    assert "report its actual\ncount as zero" in skill
    assert "Manual Phase B runs keep their context-specific" in skill
    assert "do not make copying a long\ninternal command the normal recovery path" in skill
    assert "承認UIの表示回数は0として正確に報告" in plugin_guide
    assert "長い内部commandのコピーを通常導線として要求しません" in plugin_guide


def test_approval_templates_stay_short_and_self_contained() -> None:
    skill = (
        REPO_ROOT / "skills" / "tooluseproxy-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")
    templates = [
        line.split("`", 2)[1]
        for line in skill.splitlines()
        if line.startswith("- ") and "`ToolUseProxyの操作確認｜" in line
    ]

    assert len(templates) == 12
    labels = (
        "｜行うこと：",
        "｜変更されるもの：",
        "｜外部通信：",
        "｜確認が必要な理由：",
        "｜この内容で実行してよいですか？",
    )
    for template in templates:
        assert len(template) <= 160
        positions = [template.index(label) for label in labels]
        assert positions == sorted(positions)
        assert "外部通信：ありません" in template
        assert template.endswith("｜この内容で実行してよいですか？")
        assert "なら許可" not in template
        assert "なら拒否" not in template
        assert "許可条件" not in template
        assert "`" not in template

    setup = next(value for value in templates if "このプロジェクトの保護を有効" in value)
    scan = next(value for value in templates if "守った方がよいファイルを探します" in value)
    assert "外部送信を実行前に止める" in setup
    assert "専用保存領域へ設定を保存" in setup
    assert "専用保存領域へ確認結果を記録" in scan
    assert "このプロジェクト内を安全な範囲で読むため" not in scan


def test_hook_status_messages_are_plain_japanese() -> None:
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text())
    status_messages = [
        hook["statusMessage"]
        for groups in hooks["hooks"].values()
        for group in groups
        for hook in group["hooks"]
    ]

    assert status_messages == [
        "送信前に保護対象が含まれていないか確認しています",
        "ツールの実行記録をこの端末に保存しています",
        "回答に保護対象が含まれていないか確認しています",
    ]


def test_missing_database_explains_next_step_in_japanese(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooluseproxy",
            "hook",
            "stop",
            "--data-dir",
            str(tmp_path / "data"),
        ],
        cwd=REPO_ROOT,
        input='{"hook_event_name":"Stop","cwd":"."}',
        capture_output=True,
        text=True,
        check=True,
    )
    message = json.loads(result.stdout)["systemMessage"]

    assert "このプロジェクトではまだ準備されていません" in message
    assert "ToolUseProxyをこのプロジェクトで使えるようにして" in message
    assert "database_missing" in message
    assert "手動で準備する場合のコマンド" not in message
    assert str(tmp_path) not in message
    assert "ToolUseProxy inactive" not in message
