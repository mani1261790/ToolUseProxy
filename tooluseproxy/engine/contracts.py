"""Small positive contracts for visible local operations, never command allowlists.

Unsupported syntax falls back to recorded-input classification. These contracts
say nothing about hidden shell startup files, program hooks or network isolation.
They classify communication only; they never grant an outbound permission.
"""

import shlex


def provenance_contract(node):
    """A witnessed, literal single-file read has a known content origin.

    This creates a resource read, never an independent/public value. Resource
    generation links and the current protection policy still apply. Unsupported
    syntax, missing observations and transformations require semantic review.
    """
    words = literal_words(node.get("tool_name"), node.get("input"))
    if not node.get("completed") or not words or len(words) != 2 or words[0] != "cat":
        return None
    path = words[1]
    if not path or path.startswith(("-", "/")) or any(c in path for c in "~*?[]"):
        return None
    if node.get("resolved_cwd") != node.get("workspace_root"):
        return None
    import posixpath

    if posixpath.normpath(path) != path or path.startswith("../") or path == "..":
        return None
    witnessed = [r for r in node.get("resource_observations", [])
                 if r["mode"] == "read" and r["status"] == "observed"]
    if len(witnessed) != 1 or witnessed[0]["path"] != path:
        return None
    # No shell diagnostics/envelope is mistaken for file content. Structured
    # tool responses use their existing semantic adapter instead.
    if not isinstance(node.get("output"), str):
        return None
    return dict(externality="local", complete=True,
                reason="witnessed single-file content read", dependencies=[],
                accesses=[dict(path=path, mode="read", reason="observed file content")],
                evidence_requests=[])


def literal_words(tool_name, tool_input):
    if tool_name != "Bash" or not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or len(command) > 64_000:
        return None
    if any(char in command for char in "\n\r;&|<>`$(){}\\"):
        return None
    try:
        return shlex.split(command, posix=True) or None
    except ValueError:
        return None


def communication_contract(tool_name, tool_input):
    local = local_contract(tool_name, tool_input)
    if local is not None:
        return local
    words = literal_words(tool_name, tool_input)
    if (
        words
        and len(words) > 1
        and words[0] == "git"
        and words[1]
        in {
            "push",
            "fetch",
            "pull",
            "clone",
            "ls-remote",
        }
    ):
        return dict(
            externality="external",
            complete=True,
            resources=[],
            reason="explicit_remote_operation_contract",
        )
    return None


def evidence_requirements(tool_name, tool_input):
    words = literal_words(tool_name, tool_input)
    if (
        words
        and len(words) > 1
        and words[:2]
        in [
            ["git", "push"],
            ["git", "fetch"],
            ["git", "pull"],
            ["git", "ls-remote"],
        ]
    ):
        # Only the current repository's explicit remote settings. Never walk
        # imports, executable implementations or arbitrary filesystem parents.
        return [{"path": ".git/config", "reason": "resolve named remote configuration"}]
    return []


def local_contract(tool_name, tool_input):
    if tool_name == "apply_patch":
        # The canonical name of the host's local patch operation.
        return dict(
            externality="local", complete=True, resources=[], reason="local_file_edit_contract"
        )
    words = literal_words(tool_name, tool_input)
    if not words:
        return None
    executable, args = words[0], words[1:]
    # No executable-path aliasing, env wrappers, function expansion or -c flags.
    if executable in {"pwd", "ls", "cat", "head", "tail", "wc"}:
        resources = (
            [dict(path=path, mode="read") for path in args]
            if executable == "cat" and all(not path.startswith("-") for path in args)
            else []
        )
        return dict(
            externality="local",
            complete=True,
            resources=resources,
            reason="literal_local_command_contract",
        )
    if (
        executable == "git"
        and args
        and args[0]
        in {
            "status",
            "add",
            "commit",
            "diff",
            "log",
            "show",
            "rev-parse",
            "rev-list",
            "branch",
            "reset",
            "ls-files",
        }
    ):
        # An invocation of git's local operation is local in the explicit-send
        # product boundary. Its configured hooks/helpers are outside coverage.
        # Global options (notably -c), remote commands and aliases do not match.
        return dict(
            externality="local",
            complete=True,
            resources=[],
            reason="literal_local_command_contract",
        )
    return None
