from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from hook_monitor.analysis.adapters.mcp import classify_mcp_sink_type
from hook_monitor.analysis.bash_file_parser import (
    BashSegment,
    bash_segment_command_tokens,
    bash_segment_redirection_tokens,
    parse_bash_command_plan,
)
from hook_monitor.externality.models import ExternalityEnvelope


MAX_SCRIPT_BYTES = 256 * 1024
MAX_COMMAND_BYTES = 256 * 1024

_HTTP_CLIENTS = frozenset({"curl", "http", "httpie", "wget"})
_FILE_TRANSFER_CLIENTS = frozenset({"rsync", "scp", "sftp", "ssh"})
_SOCKET_CLIENTS = frozenset({"nc", "netcat", "ncat", "socat", "telnet"})
_DNS_CLIENTS = frozenset({"dig", "host", "nslookup"})
_PYTHON_RUNTIMES = frozenset({"python", "python3", "python3.11", "python3.12"})
_NODE_RUNTIMES = frozenset({"node", "nodejs"})
_SHELL_RUNTIMES = frozenset({"bash", "dash", "sh", "zsh"})
_LOCAL_FILE_TOOLS = frozenset(
    {
        "awk",
        "cat",
        "cp",
        "cut",
        "diff",
        "find",
        "grep",
        "head",
        "ls",
        "mkdir",
        "mv",
        "pwd",
        "rg",
        "sed",
        "sort",
        "tail",
        "touch",
        "tr",
        "wc",
    }
)
_LOCAL_BUILD_OR_TEST = frozenset(
    {
        "cargo",
        "cmake",
        "go",
        "make",
        "ninja",
        "pytest",
        "ruff",
        "tsc",
    }
)
_EXECUTION_CAPABLE_LOCAL_TOOLS = frozenset({"awk", "find", "sed", "sort"})
_DEPLOYMENT_CLIENTS = frozenset({"aws", "az", "gcloud", "netlify", "vercel", "wrangler"})

_PYTHON_HTTP_MODULES = frozenset(
    {"aiohttp", "http.client", "httpx", "requests", "urllib", "urllib.request"}
)
_PYTHON_SOCKET_MODULES = frozenset(
    {"asyncio", "ftplib", "imaplib", "poplib", "smtplib", "socket", "telnetlib"}
)
_PYTHON_DNS_MODULES = frozenset({"dns", "dns.resolver"})
_PYTHON_CHILD_MODULES = frozenset({"subprocess"})

_NODE_HTTP_PATTERN = re.compile(
    r"(?:\brequire\s*\(\s*['\"](?:node:)?(?:http|https|undici)['\"]|"
    r"\bfrom\s+['\"](?:node:)?(?:http|https|undici)['\"]|\bfetch\s*\(|"
    r"\bWebSocket\s*\()"
)
_NODE_SOCKET_PATTERN = re.compile(
    r"(?:\brequire\s*\(\s*['\"](?:node:)?net['\"]|"
    r"\bfrom\s+['\"](?:node:)?net['\"]|\bnet\.(?:connect|createConnection)\s*\()"
)
_NODE_DNS_PATTERN = re.compile(
    r"(?:\brequire\s*\(\s*['\"](?:node:)?dns['\"]|"
    r"\bfrom\s+['\"](?:node:)?dns['\"]|\bdns\.(?:lookup|resolve)\s*\()"
)
_NODE_CHILD_PATTERN = re.compile(
    r"(?:\brequire\s*\(\s*['\"](?:node:)?child_process['\"]|"
    r"\bfrom\s+['\"](?:node:)?child_process['\"]|"
    r"\b(?:exec|execFile|spawn|fork)\s*\()"
)
_NODE_DYNAMIC_PATTERN = re.compile(r"(?:\beval\s*\(|\bFunction\s*\(|\bimport\s*\([^)]*\))")


@dataclass(frozen=True)
class StaticExternalityResult:
    verdict: Literal["external", "local", "unknown"]
    reason_codes: tuple[str, ...]
    envelope: ExternalityEnvelope


@dataclass
class _AnalysisState:
    executable_classes: set[str]
    capabilities: set[str]
    risk_signals: set[str]
    counts: dict[str, int]
    coverage: Literal["complete", "partial", "opaque"] = "complete"

    @classmethod
    def empty(cls) -> _AnalysisState:
        return cls(
            executable_classes=set(),
            capabilities=set(),
            risk_signals=set(),
            counts={
                "dynamic_token_count": 0,
                "file_read_count": 0,
                "pipeline_count": 0,
                "redirection_count": 0,
                "script_file_count": 0,
                "segment_count": 0,
            },
        )

    def lower_coverage(self, coverage: Literal["partial", "opaque"]) -> None:
        order = {"complete": 0, "partial": 1, "opaque": 2}
        if order[coverage] > order[self.coverage]:
            self.coverage = coverage


def analyze_bash_externality(
    command: str,
    *,
    workspace_root: Path,
    cwd: Path | None = None,
) -> StaticExternalityResult:
    """Build a closed, value-free summary without executing the command."""
    state = _AnalysisState.empty()
    if len(command.encode("utf-8", errors="surrogatepass")) > MAX_COMMAND_BYTES:
        state.risk_signals.add("script_size_exceeded")
        state.lower_coverage("opaque")
        return _result("bash", state)
    plan = parse_bash_command_plan(command)
    if plan is None:
        state.risk_signals.add("unsupported_shell_syntax")
        state.lower_coverage("opaque")
        return _result("bash", state)

    state.counts["segment_count"] = len(plan.segments)
    state.counts["pipeline_count"] = sum(
        segment.connector_from == "pipe" for segment in plan.segments
    )
    root = Path(workspace_root).resolve()
    effective_cwd = Path(cwd or root).resolve()
    if not _is_within(effective_cwd, root):
        state.risk_signals.add("outside_workspace_reference")
        state.lower_coverage("opaque")
        effective_cwd = root

    for segment in plan.segments:
        state.counts["file_read_count"] += sum(
            operation.operation == "read" for operation in segment.operations
        )
        state.counts["redirection_count"] += sum(
            token.is_operator for token in bash_segment_redirection_tokens(segment)
        )
        dynamic_count = sum(not token.is_static_literal for token in segment.tokens)
        state.counts["dynamic_token_count"] += dynamic_count
        if dynamic_count:
            state.risk_signals.add("dynamic_shell_token")
            state.lower_coverage("partial")
        if any(token.is_assignment_word for token in segment.tokens):
            state.risk_signals.add("environment_override")
            state.lower_coverage("partial")
        if any(
            operation.path.startswith(("/dev/tcp/", "/dev/udp/"))
            for operation in segment.operations
        ):
            state.capabilities.add("socket")
        _analyze_segment(segment, state, root=root, cwd=effective_cwd)
    return _result("bash", state)


def analyze_mcp_externality(
    tool_name: str | None,
    payload: dict[str, Any],
) -> StaticExternalityResult:
    """Summarize MCP externality without retaining server, tool, or argument values."""
    state = _AnalysisState.empty()
    state.executable_classes.add("mcp_tool")
    state.counts["segment_count"] = 1
    if classify_mcp_sink_type(tool_name, payload) is not None:
        state.capabilities.add("mcp_mutation")
    else:
        state.risk_signals.add("mcp_unclassified")
        state.lower_coverage("partial")
    return _result("mcp", state)


def _analyze_segment(
    segment: BashSegment,
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> None:
    words = bash_segment_command_tokens(segment)
    if not words:
        non_operators = [token for token in segment.tokens if not token.is_operator]
        if non_operators and all(token.is_assignment_word for token in non_operators):
            return
        state.executable_classes.add("custom_or_unknown")
        state.risk_signals.add("unknown_executable")
        state.lower_coverage("opaque")
        return
    raw_program = words[0].value
    if "/" in raw_program or "\\" in raw_program:
        state.executable_classes.add("custom_or_unknown")
        state.risk_signals.add("untrusted_executable_path")
        state.lower_coverage("opaque")
        return
    program = _basename(raw_program)
    arguments = [token.value for token in words[1:]]

    if program in _HTTP_CLIENTS:
        state.executable_classes.add("http_client")
        state.capabilities.add("http")
        return
    if program in _FILE_TRANSFER_CLIENTS:
        state.executable_classes.add("file_transfer_client")
        state.capabilities.add("external_file_transfer")
        return
    if program in _SOCKET_CLIENTS:
        state.executable_classes.add("socket_client")
        state.capabilities.add("socket")
        return
    if program in _DNS_CLIENTS:
        state.executable_classes.add("dns_client")
        state.capabilities.add("dns")
        return
    if program == "git":
        state.executable_classes.add("remote_vcs_client")
        if arguments[:1] == ["push"]:
            state.capabilities.add("remote_vcs_write")
        else:
            state.lower_coverage("partial")
        return
    if _is_package_publish(program, arguments):
        state.executable_classes.add("package_publisher")
        state.capabilities.add("package_publish")
        return
    if program in _DEPLOYMENT_CLIENTS:
        state.executable_classes.add("deployment_client")
        state.capabilities.add("deployment")
        return
    if program in _PYTHON_RUNTIMES:
        state.executable_classes.add("python_runtime")
        _analyze_python_invocation(arguments, state, root=root, cwd=cwd)
        return
    if program in _NODE_RUNTIMES:
        state.executable_classes.add("node_runtime")
        _analyze_node_invocation(arguments, state, root=root, cwd=cwd)
        return
    if program in _SHELL_RUNTIMES:
        state.executable_classes.add("shell_runtime")
        _analyze_shell_invocation(arguments, state, root=root, cwd=cwd)
        return
    if program in _LOCAL_FILE_TOOLS:
        state.executable_classes.add("local_file_tool")
        if program in _EXECUTION_CAPABLE_LOCAL_TOOLS:
            state.capabilities.add("child_process")
            state.risk_signals.add("execution_capable_tool")
            state.lower_coverage("partial")
        return
    if program in _LOCAL_BUILD_OR_TEST:
        state.executable_classes.add("local_build_or_test")
        if _is_publish_subcommand(program, arguments):
            state.capabilities.add("package_publish")
            state.executable_classes.add("package_publisher")
        else:
            state.capabilities.add("child_process")
            state.risk_signals.add("execution_capable_tool")
            state.lower_coverage("partial")
        return

    state.executable_classes.add("custom_or_unknown")
    state.risk_signals.add("unknown_executable")
    state.lower_coverage("opaque")


def _analyze_python_invocation(
    arguments: list[str],
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> None:
    # Python imports and calls require whole-program analysis to prove locality.
    state.lower_coverage("partial")
    source = _inline_argument(arguments, "-c")
    if source is not None:
        state.risk_signals.add("inline_program")
        _analyze_python_source(source, state)
        return
    if "-m" in arguments:
        state.lower_coverage("partial")
        module_index = arguments.index("-m") + 1
        if module_index < len(arguments):
            _apply_python_module(arguments[module_index], state)
        return
    script = _first_script_argument(arguments)
    if script is None:
        state.lower_coverage("partial")
        return
    source = _read_workspace_script(script, state, root=root, cwd=cwd)
    if source is not None:
        _analyze_python_source(source, state)


def _analyze_node_invocation(
    arguments: list[str],
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> None:
    # Node imports and calls require whole-program analysis to prove locality.
    state.lower_coverage("partial")
    source = _inline_argument(arguments, "-e")
    if source is None:
        source = _inline_argument(arguments, "--eval")
    if source is not None:
        state.risk_signals.add("inline_program")
        _analyze_node_source(source, state)
        return
    script = _first_script_argument(arguments)
    if script is None:
        state.lower_coverage("partial")
        return
    source = _read_workspace_script(script, state, root=root, cwd=cwd)
    if source is not None:
        _analyze_node_source(source, state)


def _analyze_shell_invocation(
    arguments: list[str],
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> None:
    source = _inline_argument(arguments, "-c")
    if source is not None:
        state.risk_signals.add("inline_program")
        nested = analyze_bash_externality(source, workspace_root=root, cwd=cwd)
        _merge_nested(nested, state)
        return
    script = _first_script_argument(arguments)
    if script is None:
        state.lower_coverage("partial")
        return
    source = _read_workspace_script(script, state, root=root, cwd=cwd)
    if source is None:
        return
    _analyze_shell_source(source, state, root=root, cwd=cwd)


def _analyze_shell_source(
    source: str,
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> None:
    lines = source.splitlines()
    if len(lines) > 1_000:
        state.risk_signals.add("script_size_exceeded")
        state.lower_coverage("opaque")
        return
    analyzed_line = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        analyzed_line = True
        nested = analyze_bash_externality(stripped, workspace_root=root, cwd=cwd)
        _merge_nested(nested, state)
    # Per-line parsing cannot prove the semantics of an entire shell script.
    state.lower_coverage("partial")
    if not analyzed_line:
        state.risk_signals.add("script_parse_failed")


def _read_workspace_script(
    script: str,
    state: _AnalysisState,
    *,
    root: Path,
    cwd: Path,
) -> str | None:
    candidate = Path(script)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        state.risk_signals.add("script_parse_failed")
        state.lower_coverage("opaque")
        return None
    if not _is_within(resolved, root) or not resolved.is_file():
        state.risk_signals.add("outside_workspace_reference")
        state.lower_coverage("opaque")
        return None
    try:
        size = resolved.stat().st_size
    except OSError:
        state.risk_signals.add("script_parse_failed")
        state.lower_coverage("opaque")
        return None
    if size > MAX_SCRIPT_BYTES:
        state.risk_signals.add("script_size_exceeded")
        state.lower_coverage("opaque")
        return None
    try:
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        state.risk_signals.add("script_parse_failed")
        state.lower_coverage("opaque")
        return None
    state.counts["script_file_count"] += 1
    return source


def _analyze_python_source(source: str, state: _AnalysisState) -> None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        state.risk_signals.add("script_parse_failed")
        state.lower_coverage("opaque")
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _apply_python_module(alias.name, state)
        elif isinstance(node, ast.ImportFrom) and node.module:
            _apply_python_module(node.module, state)
        elif isinstance(node, ast.Call):
            name = _python_call_name(node.func)
            if name in {"eval", "exec", "__import__"}:
                state.risk_signals.add("dynamic_code")
                state.lower_coverage("partial")
            if name.startswith("subprocess.") or name in {"os.popen", "os.system"}:
                state.capabilities.add("child_process")
                state.lower_coverage("partial")


def _apply_python_module(module: str, state: _AnalysisState) -> None:
    if module in _PYTHON_HTTP_MODULES or any(
        module.startswith(f"{prefix}.") for prefix in _PYTHON_HTTP_MODULES
    ):
        state.capabilities.add("http")
    if module in _PYTHON_SOCKET_MODULES or any(
        module.startswith(f"{prefix}.") for prefix in _PYTHON_SOCKET_MODULES
    ):
        state.capabilities.add("socket")
    if module in _PYTHON_DNS_MODULES or any(
        module.startswith(f"{prefix}.") for prefix in _PYTHON_DNS_MODULES
    ):
        state.capabilities.add("dns")
    if module in _PYTHON_CHILD_MODULES:
        state.capabilities.add("child_process")
        state.lower_coverage("partial")


def _analyze_node_source(source: str, state: _AnalysisState) -> None:
    if _NODE_HTTP_PATTERN.search(source):
        state.capabilities.add("http")
    if _NODE_SOCKET_PATTERN.search(source):
        state.capabilities.add("socket")
    if _NODE_DNS_PATTERN.search(source):
        state.capabilities.add("dns")
    if _NODE_CHILD_PATTERN.search(source):
        state.capabilities.add("child_process")
        state.lower_coverage("partial")
    if _NODE_DYNAMIC_PATTERN.search(source):
        state.risk_signals.add("dynamic_code")
        state.lower_coverage("partial")


def _result(tool_family: Literal["bash", "mcp"], state: _AnalysisState) -> StaticExternalityResult:
    envelope = ExternalityEnvelope.create(
        tool_family=tool_family,
        analysis_coverage=state.coverage,
        executable_classes=state.executable_classes,
        capabilities=state.capabilities,
        risk_signals=state.risk_signals,
        counts=state.counts,
    )
    external_capabilities = state.capabilities - {"child_process"}
    if external_capabilities:
        verdict: Literal["external", "local", "unknown"] = "external"
        reasons = ("known_external_operation",)
    elif state.coverage == "complete" and not state.risk_signals and state.executable_classes:
        verdict = "local"
        reasons = ("known_local_only",)
    else:
        verdict = "unknown"
        reasons = ("insufficient_evidence",)
    return StaticExternalityResult(verdict, reasons, envelope)


def _merge_nested(nested: StaticExternalityResult, state: _AnalysisState) -> None:
    state.executable_classes.update(nested.envelope.executable_classes)
    state.capabilities.update(nested.envelope.capabilities)
    state.risk_signals.update(nested.envelope.risk_signals)
    nested_counts = dict(nested.envelope.counts)
    for key in state.counts:
        if key in {"segment_count", "pipeline_count", "redirection_count"}:
            state.counts[key] += nested_counts[key]
    if nested.envelope.analysis_coverage == "opaque":
        state.lower_coverage("opaque")
    elif nested.envelope.analysis_coverage == "partial":
        state.lower_coverage("partial")


def _inline_argument(arguments: list[str], flag: str) -> str | None:
    try:
        index = arguments.index(flag)
    except ValueError:
        return None
    if index + 1 >= len(arguments):
        return None
    return arguments[index + 1]


def _first_script_argument(arguments: list[str]) -> str | None:
    skip_next = False
    for argument in arguments:
        if skip_next:
            skip_next = False
            continue
        if argument in {"-c", "-e", "-m", "--eval", "--require"}:
            skip_next = True
            continue
        if argument.startswith("-"):
            continue
        return argument
    return None


def _python_call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_package_publish(program: str, arguments: list[str]) -> bool:
    if program in {"npm", "pnpm"} and arguments[:1] == ["publish"]:
        return True
    if program == "yarn" and arguments[:2] == ["npm", "publish"]:
        return True
    if program == "twine" and arguments[:1] == ["upload"]:
        return True
    if program == "docker" and arguments[:1] == ["push"]:
        return True
    return _is_publish_subcommand(program, arguments)


def _is_publish_subcommand(program: str, arguments: list[str]) -> bool:
    return program == "cargo" and arguments[:1] == ["publish"]


def _basename(program: str) -> str:
    return program.rsplit("/", 1)[-1]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
