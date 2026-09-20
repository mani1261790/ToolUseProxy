from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.build_authority_admin import build
from tooluseproxy import authority_admin
from tooluseproxy.authority_state import AuthorityError, _Store


@pytest.fixture
def admin_fixture(tmp_path):
    directory = tmp_path / "authority"
    workspace = tmp_path / "workspace"
    data = tmp_path / "data"
    for path in (directory, workspace, data):
        path.mkdir(mode=0o755)
    store = _Store(directory, owner=os.geteuid())
    return store, dict(uid=os.getuid(), workspace=str(workspace), data_dir=str(data))


def test_interactive_lifecycle_preserves_user_files(admin_fixture):
    store, target = admin_fixture
    for name in ("workspace", "data_dir"):
        (Path(target[name]) / "fixture.txt").write_text("unchanged")
    review = authority_admin._review(store, **target, action="enroll")
    initial = authority_admin._apply_review(store, review, "確認して適用")
    assert initial.phase == "active"
    review = authority_admin._review(store, **target, action="deactivate")
    stopped = authority_admin._apply_review(store, review, "確認して適用")
    assert stopped.phase == "inactive"
    assert authority_admin._apply_review(store, review, "確認して適用") == stopped
    restored = authority_admin._review(store, **target, action="reactivate")
    assert authority_admin._apply_review(store, restored, "確認して適用").phase == "active"
    with pytest.raises(AuthorityError, match="generation_conflict"):
        authority_admin._apply_review(store, review, "確認して適用")
    for name in ("workspace", "data_dir"):
        assert (Path(target[name]) / "fixture.txt").read_text() == "unchanged"


@pytest.mark.parametrize("answer", ["yes", "", "--yes", "確認して適用\n", "cancel"])
def test_confirmation_is_exact_and_cancel_does_not_write(admin_fixture, answer):
    store, target = admin_fixture
    review = authority_admin._review(store, **target, action="enroll")
    with pytest.raises(AuthorityError, match="administrator_cancelled"):
        authority_admin._apply_review(store, review, answer)
    assert list(store.directory.iterdir()) == []


@pytest.mark.parametrize("elapsed", [-1, 120, 121])
@pytest.mark.parametrize("started", [8.003, 1000.0])
def test_expired_review_cannot_apply(admin_fixture, monkeypatch, elapsed, started):
    store, target = admin_fixture
    monkeypatch.setattr(authority_admin.time, "monotonic", lambda: started)
    review = authority_admin._review(store, **target, action="enroll")
    monkeypatch.setattr(authority_admin.time, "monotonic", lambda: review.started + elapsed)
    with pytest.raises(AuthorityError, match="review_expired"):
        authority_admin._apply_review(store, review, "確認して適用")
    assert list(store.directory.iterdir()) == []


@pytest.mark.parametrize("key", ["workspace", "data_dir"])
def test_directory_replacement_during_confirmation_is_rejected(admin_fixture, key):
    store, target = admin_fixture
    review = authority_admin._review(store, **target, action="enroll")
    path = Path(target[key])
    path.rename(path.with_name(path.name + "-old"))
    path.mkdir()
    with pytest.raises(AuthorityError, match="target_changed"):
        authority_admin._apply_review(store, review, "確認して適用")
    assert list(store.directory.iterdir()) == []


def test_symlink_and_target_substitution_are_rejected(admin_fixture, tmp_path):
    store, target = admin_fixture
    review = authority_admin._review(store, **target, action="enroll")
    link = tmp_path / "link"
    link.symlink_to(target["workspace"])
    with pytest.raises(AuthorityError, match="absolute_directory"):
        authority_admin._review(store, **{**target, "workspace": str(link)}, action="enroll")
    other = tmp_path / "other"
    other.mkdir()
    forged = replace(review, target=replace(review.target, workspace=str(other)))
    with pytest.raises(AuthorityError, match="target_changed"):
        authority_admin._apply_review(store, forged, "確認して適用")


def test_finish_only_drains_the_existing_approved_operation(admin_fixture):
    store, target = admin_fixture
    enrollment = authority_admin._review(store, **target, action="enroll")
    authority_admin._apply_review(store, enrollment, "確認して適用")
    with store.lease(enrollment.target):
        review = authority_admin._review(store, **target, action="deactivate")
        assert authority_admin._apply_review(store, review, "確認して適用").phase == "deactivating"
        finish = authority_admin._review(store, **target, action="finish")
        assert finish.operation == review.operation
    assert authority_admin._apply_review(store, finish, "確認して適用").phase == "inactive"
    with pytest.raises(AuthorityError, match="not_deactivating"):
        authority_admin._review(store, **target, action="finish")


def test_confirmation_display_escapes_control_characters(admin_fixture, capsys):
    store, target = admin_fixture
    review = authority_admin._review(store, **target, action="enroll")
    display = replace(review, target=replace(review.target, workspace="/project\n\x1b[2J"))
    authority_admin._render_review(display)
    output = capsys.readouterr().out
    assert "\\n\\x1b" in output
    assert "\x1b" not in output
    assert "OS認証の代わりではありません" in output


def test_standalone_artifact_is_reproducible_and_denies_nonadmin(tmp_path):
    payload = build()
    assert build() == payload
    assert b"from tooluseproxy" not in payload
    artifact = tmp_path / "authority-admin.py"
    artifact.write_bytes(payload)
    interpreters = [sys.executable]
    if sys.platform == "darwin":
        interpreters.append("/usr/bin/python3")
    for interpreter in interpreters:
        help_result = subprocess.run([interpreter, "-I", "-S", str(artifact), "--help"],
                                     capture_output=True, text=True, timeout=20)
        assert help_result.returncode == 0, help_result.stderr
        result = subprocess.run(
            [interpreter, "-I", "-S", str(artifact), "deactivate", "--uid", "501",
             "--workspace", str(tmp_path), "--data-dir", str(tmp_path)],
            input="確認して適用\n", capture_output=True, text=True, timeout=20,
            env={**os.environ, "TOOLUSEPROXY_UNSETUP_APPROVED": "1"},
        )
        assert result.returncode == 1
        assert "administrator_" in result.stderr
        assert result.stdout == ""
    assert sorted(p.name for p in tmp_path.iterdir()) == ["authority-admin.py"]


def test_review_payload_does_not_include_source_contents(admin_fixture):
    store, target = admin_fixture
    source = Path(target["workspace"]) / "protected_sources.json"
    source.write_text("synthetic-private-manifest")
    review = authority_admin._review(store, **target, action="enroll")
    assert "synthetic-private-manifest" not in json.dumps(review.target.payload())
