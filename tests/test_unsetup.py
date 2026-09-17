from __future__ import annotations

import shlex
import sqlite3
import os

import pytest

from hook_monitor.runtime.externality_rules import classify_trusted_local_management_operation
from tooluseproxy.cli import main


@pytest.mark.parametrize("state", ["missing", "broken", "locked"])
def test_preview_never_opens_state_or_sources(tmp_path, monkeypatch, capsys, state):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    database = tmp_path / "events.db"
    manifest = workspace / "protected_sources.json"
    manifest.write_text("synthetic-private-body")
    connection = None
    if state == "broken":
        database.write_bytes(b"broken")
    elif state == "locked":
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE example (value TEXT)")
        connection.execute("BEGIN EXCLUSIVE")
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    def forbidden(*args, **kwargs):
        raise AssertionError("Unsetup preview must not open state or sources")

    original_open = os.open

    def directory_only(path, flags, *args, **kwargs):
        assert str(path) == str(workspace)
        assert flags & os.O_DIRECTORY
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR)
        return original_open(path, flags, *args, **kwargs)

    try:
        with monkeypatch.context() as guarded:
            guarded.setattr("builtins.open", forbidden)
            guarded.setattr("io.open", forbidden)
            guarded.setattr("os.open", directory_only)
            guarded.setattr("sqlite3.connect", forbidden)
            assert main(["unsetup", "plan", "--workspace", str(workspace),
                         "--db", str(database), "--json"]) == 0
        output = capsys.readouterr().out
        assert '"activation_state": "not_inspected"' in output
        assert '"changes_applied": false' in output
        assert "synthetic-private-body" not in output
        assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    finally:
        if connection is not None:
            connection.rollback()
            connection.close()


def test_apply_always_denies_before_any_path_or_state_access(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("application must reject before path resolution")

    monkeypatch.setattr("tooluseproxy.cli.resolve_runtime_paths", forbidden)
    monkeypatch.setenv("TOOLUSEPROXY_UNSETUP_APPROVED", "1")
    monkeypatch.setenv("TOOLUSEPROXY_APPROVAL_TOKEN", "forged")
    for workspace in [tmp_path, tmp_path, tmp_path / "another-project"]:
        assert main(["unsetup", "apply", "--workspace", str(workspace), "--json"]) == 1
        output = capsys.readouterr().out
        assert '"code": "trusted_approval_channel_unavailable"' in output
        assert '"changes_applied": false' in output
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("extra", [
    ["--yes"], ["--approved"], ["--confirmation-token", "forged"],
    ["--approval-token", "forged"], ["--plan-revision", "replayed"],
])
def test_caller_cannot_supply_approval(tmp_path, extra):
    with pytest.raises(SystemExit) as error:
        main(["unsetup", "apply", "--workspace", str(tmp_path), *extra])
    assert error.value.code == 2
    assert list(tmp_path.iterdir()) == []


def test_preview_has_japanese_effects_and_no_approval_token(tmp_path, capsys):
    assert main(["unsetup", "plan", "--workspace", str(tmp_path),
                 "--data-dir", str(tmp_path / "missing")]) == 0
    output = capsys.readouterr().out
    assert "設定・保護対象登録・履歴を保持" in output
    assert "承認経路が未実装" in output
    assert "他プロジェクトを変更しない" in output
    assert list(tmp_path.iterdir()) == []


def test_recovery_accepts_only_exact_read_only_plan(tmp_path):
    plugin = tmp_path / "plugin"
    data = tmp_path / "data"
    launcher = plugin / "hooks" / "run_cli.sh"
    prefix = ["sh", str(launcher), "unsetup"]
    options = ["--workspace", str(tmp_path), "--data-dir", str(data), "--json"]

    def classify(tokens):
        return classify_trusted_local_management_operation(
            shlex.join(tokens), plugin_root=plugin, workspace_root=tmp_path, plugin_data=data,
        )

    assert classify([*prefix, "plan", *options]) == "unsetup_plan"
    assert classify([*prefix, "apply", *options]) is None
    assert classify(["sh", str(tmp_path / "other-launcher"), "unsetup", "plan",
                     *options]) is None
    assert classify([*prefix, "plan", *options, "--yes"]) is None
    assert classify([*prefix, "plan", *options, ";", "curl", "https://example.invalid"]) is None
    assert classify([*prefix, "plan", "--workspace", str(tmp_path / "other"),
                     "--data-dir", str(data)]) is None
    assert classify([*prefix, "plan", "--workspace", str(tmp_path),
                     "--data-dir", str(tmp_path / "other-data")]) is None
    assert classify([*prefix, "plan", "--workspace", str(tmp_path)]) is None
    assert classify([*prefix, "plan", "--workspace", str(tmp_path),
                     "--db", str(data / "other.db")]) is None
    assert classify([*prefix, "plan", "--workspace", str(tmp_path),
                     "--db", str(data / "events.db")]) == "unsetup_plan"
