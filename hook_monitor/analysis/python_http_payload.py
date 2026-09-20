"""Extract fully literal HTTP inputs from closed, isolated Python programs.

This module never executes Python code and does not make an allow decision.
Unsupported programs return None. Callers must still compare all extracted
values with protected sources and verify their execution-environment boundary.
"""
from __future__ import annotations

import ast
import base64
import json
import time
from urllib.parse import quote, quote_plus, urlsplit

from hook_monitor.analysis.mcp_payload_evidence import verify_mcp_payload_against_sources
from hook_monitor.analysis.sink_payload_evidence import source_comparison_limit_reason
from hook_monitor.runtime.models import SourceChunk

from hook_monitor.analysis.bash_file_parser import (
    bash_segment_argv_tokens, bash_segment_command_tokens, parse_bash_command_plan,
)

MAX_SCRIPT_BYTES = 16384
MAX_BODY_BYTES = 8192


def urllib_literal_script(url: str, body: bytes, headers: dict[str, str]) -> str:
    """Canonical urllib form: no site initialization or environment proxy lookup."""
    return (
        "import urllib.request,base64; from pathlib import Path; "
        f"payload={body!r}; "
        f"request=urllib.request.Request({url!r},data=payload,headers={headers!r},method='POST'); "
        "opener=urllib.request.OpenerDirector(); "
        "opener.add_handler(urllib.request.HTTPHandler()); "
        "response=opener.open(request,timeout=2); response.read(); "
        "assert response.status == 204; response.close()"
    )


def http_client_literal_script(host: str, port: int, path: str,
                               body: bytes, headers: dict[str, str]) -> str:
    return (
        "import base64,urllib.request,http.client; from pathlib import Path; "
        f"payload={body!r}; "
        f"connection=http.client.HTTPConnection({host!r},{port!r},timeout=2); "
        f"connection.request('POST',{path!r},body=payload,headers={headers!r}); "
        "response=connection.getresponse(); response.read(); "
        "assert response.status == 204; connection.close()"
    )


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return parent + '.' + node.attr if parent else None
    return None


def _constant(node, kind):
    if not isinstance(node, ast.Constant) or type(node.value) is not kind:
        raise ValueError
    return node.value


def _headers(node):
    if not isinstance(node, ast.Dict) or len(node.keys) > 8:
        raise ValueError
    result = {}
    for key, value in zip(node.keys, node.values):
        key, value = _constant(key, str), _constant(value, str)
        if (key in result or not key or any(c in key + value for c in '\r\n\0')
                or len(key.encode()) > 256 or len(value.encode()) > 256):
            raise ValueError
        result[key] = value
    return result


def _keyword(call, name):
    found = [keyword.value for keyword in call.keywords if keyword.arg == name]
    if len(found) != 1:
        raise ValueError
    return found[0]


def inspect_literal_python_http(command: str) -> tuple[str, ...] | None:
    """Return outbound literal values only; never infer safety from no match here."""
    try:
        if not isinstance(command, str) or len(command.encode()) > MAX_SCRIPT_BYTES + 256:
            return None
        plan = parse_bash_command_plan(command)
        if plan is None or len(plan.segments) != 1:
            return None
        segment = plan.segments[0]
        tokens = bash_segment_command_tokens(segment)
        if (segment.connector_from is not None or len(tokens) != len(bash_segment_argv_tokens(segment))
                or any(not t.is_static_literal for t in tokens)
                or any(t.is_operator for t in segment.tokens)):
            return None
        argv = [t.value for t in tokens]
        if (len(argv) != 6 or argv[0] not in {'python', 'python3', '/usr/bin/python3', '/usr/local/bin/python'}
                or argv[1:5] != ['-I', '-S', '-B', '-c']):
            return None
        script = argv[5]
        if len(script.encode()) > MAX_SCRIPT_BYTES:
            return None
        tree = ast.parse(script)
        nodes = list(ast.walk(tree))
        if len(nodes) > 220:
            return None
        payloads = [n for n in tree.body if isinstance(n, ast.Assign)
                    and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id == 'payload']
        if len(payloads) != 1:
            return None
        body = _constant(payloads[0].value, bytes)
        if len(body) > MAX_BODY_BYTES:
            return None
        text = body.decode('utf-8')
        calls = [n for n in nodes if isinstance(n, ast.Call)]
        requests = [c for c in calls if _name(c.func) == 'urllib.request.Request']
        connections = [c for c in calls if _name(c.func) == 'http.client.HTTPConnection']
        if len(requests) == 1 and not connections:
            request = requests[0]
            if len(request.args) != 1:
                return None
            url = _constant(request.args[0], str)
            target = urlsplit(url)
            if target.scheme != 'http' or not target.hostname or len(url.encode()) > 2048:
                return None
            headers = _headers(_keyword(request, 'headers'))
            expected = urllib_literal_script(url, body, headers)
            values = [url, text]
        elif len(connections) == 1 and not requests:
            connection = connections[0]
            if len(connection.args) != 2:
                return None
            host, port = _constant(connection.args[0], str), _constant(connection.args[1], int)
            sends = [c for c in calls if _name(c.func) == 'connection.request']
            if (not host or len(host.encode()) > 253 or not 1 <= port <= 65535
                    or len(sends) != 1 or len(sends[0].args) != 2):
                return None
            path = _constant(sends[0].args[1], str)
            if not path.startswith('/') or len(path.encode()) > 2048:
                return None
            headers = _headers(_keyword(sends[0], 'headers'))
            expected = http_client_literal_script(host, port, path, body, headers)
            values = [host, str(port), path, text]
        else:
            return None
        if ast.dump(tree) != ast.dump(ast.parse(expected)):
            return None
        return tuple([*values, *(part for pair in headers.items() for part in pair)])
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None


def verified_literal_python_http_segments(
    command: str, *, workspace_id: str, source_chunks: tuple[SourceChunk, ...],
) -> frozenset[int]:
    """Verify a closed program's complete outbound literals against scoped sources.

    This retains the runtime's existing lineage decisions. Unknown syntax,
    incomplete comparison or a protected match never grants an exemption.
    Standard interpreter/library integrity is an execution prerequisite, as for
    other statically inspected command adapters; this is not a Python sandbox.
    """
    values = inspect_literal_python_http(command)
    if values is None:
        return frozenset()
    chunks = tuple(c for c in source_chunks if c.workspace_id == workspace_id)
    if source_comparison_limit_reason(chunks) is not None:
        return frozenset()
    # Preserve order and duplicates: secrets may span headers or URL/body.
    submitted = (*values, ''.join(values), '\n'.join(values))
    deadline = time.monotonic() + 0.2
    for chunk in chunks:
        for text in {chunk.text, chunk.text.strip()}:
            if not text:
                continue
            raw = text.encode('utf-8')
            variants = (text, base64.b64encode(raw).decode(),
                        base64.urlsafe_b64encode(raw).decode(), raw.hex(),
                        raw.hex().upper(), quote(text, safe=''), quote_plus(text),
                        json.dumps(text, ensure_ascii=True)[1:-1])
            for value in submitted:
                if time.monotonic() >= deadline or any(v in value for v in variants):
                    return frozenset()
    # Also retain the existing normalization and similarity source-binding rules.
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms <= 0:
        return frozenset()
    verification = verify_mcp_payload_against_sources(
        {'outbound': list(submitted)}, chunks, time_budget_ms=remaining_ms,
    )
    return frozenset({0}) if verification.status == 'safe' else frozenset()
