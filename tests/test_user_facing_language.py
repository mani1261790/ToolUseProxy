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

    assert "ToolUseProxyの確認｜内容：...｜変更：...｜通信：...｜理由：...｜許可：..." in skill
    assert "このファイルをToolUseProxyで守りますか？" in skill
    assert "`守る` / `今回は見送る` / `今後は候補に出さない`" in skill
    assert "Never require the user to" in skill
    assert "reply with the English command words" in skill
    assert "Never require or compare against" in skill
    assert "not trigger strings" in skill
    assert "Never ask the user to repeat one of the examples verbatim" in skill


def test_approval_templates_stay_short_and_self_contained() -> None:
    skill = (
        REPO_ROOT / "skills" / "tooluseproxy-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")
    templates = [
        line.split("`", 2)[1]
        for line in skill.splitlines()
        if line.startswith("- ") and "`ToolUseProxyの確認｜" in line
    ]

    assert len(templates) == 10
    labels = ("｜内容：", "｜変更：", "｜通信：", "｜理由：", "｜許可：")
    for template in templates:
        assert len(template) <= 160
        positions = [template.index(label) for label in labels]
        assert positions == sorted(positions)
        assert "通信：なし" in template
        assert "`" not in template


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
        "ツールの実行記録をこのMacに保存しています",
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
    assert "ToolUseProxy inactive" not in message
