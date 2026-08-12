from __future__ import annotations

import json
import os
import re
import selectors
import statistics
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPORT_SCHEMA_VERSION = 1
RUNNER_VERSION = "codex-network-live-v1"
SYNTHETIC_CASE_ID = "managed-https-decline"
_SYNTHETIC_HOST = "example.com"
_SYNTHETIC_URL = f"https://{_SYNTHETIC_HOST}/"
_MAX_LINE_BYTES = 2 * 1024 * 1024
_MAX_STDERR_BYTES = 256 * 1024
_VERSION_PATTERN = re.compile(r"^codex-cli ([0-9][A-Za-z0-9.+-]*)$")


class CodexNetworkLiveError(RuntimeError):
    """Raised when the isolated Codex network probe cannot complete safely."""


@dataclass(frozen=True)
class LiveObservation:
    command_item_count: int
    network_approval_count: int
    general_approval_count: int
    exact_item_id_join: bool
    context_matches_fixture: bool
    approval_latency_ms: float | None
    turn_completed: bool
    mock_request_count: int
    otel_request_count: int
    otel_network_event_count: int
    otel_other_event_count: int
    otel_parse_error_count: int
    otel_execution_id_count: int
    otel_raw_capable_event_count: int
    otel_context_matches_fixture: bool
    otel_conversation_join: bool
    otel_latency_ms: float | None


@dataclass
class _MockState:
    workspace: Path
    request_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def next_response(self) -> bytes:
        with self.lock:
            self.request_count += 1
            request_number = self.request_count
        if request_number == 1:
            output = [_function_call_item(self.workspace)]
            events = _function_call_events(output[0], request_number)
        else:
            output = [_message_item()]
            events = [
                {
                    "type": "response.completed",
                    "response": _response(output, request_number),
                }
            ]
        text = "".join(
            f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
            for event in events
        )
        return (text + "data: [DONE]\n\n").encode("utf-8")


@dataclass
class _OtelState:
    request_count: int = 0
    network_event_count: int = 0
    other_event_count: int = 0
    parse_error_count: int = 0
    execution_id_count: int = 0
    raw_capable_event_count: int = 0
    context_matches_fixture: bool = True
    conversation_join: bool = True
    expected_conversation_id: str | None = None
    command_started_at: float | None = None
    network_event_latency_ms: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def set_turn_context(self, conversation_id: str, command_started_at: float) -> None:
        with self.lock:
            self.expected_conversation_id = conversation_id
            self.command_started_at = command_started_at

    def observe(self, payload: bytes) -> None:
        try:
            document = json.loads(payload)
            records = _otel_log_records(document)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            with self.lock:
                self.request_count += 1
                self.parse_error_count += 1
            return

        with self.lock:
            self.request_count += 1
            for record in records:
                attributes = _otel_attributes(record)
                event_name = attributes.get("event.name")
                if event_name != "codex.network_proxy.policy_decision":
                    self.other_event_count += 1
                    if event_name == "codex.tool_result":
                        self.raw_capable_event_count += 1
                    continue
                self.network_event_count += 1
                if isinstance(attributes.get("execution.id"), str):
                    self.execution_id_count += 1
                self.context_matches_fixture = self.context_matches_fixture and (
                    attributes.get("network.policy.scope") == "domain"
                    and attributes.get("network.policy.decision") == "deny"
                    and attributes.get("network.policy.source") == "baseline_policy"
                    and attributes.get("network.policy.reason") == "not_allowed"
                    and attributes.get("network.transport.protocol") == "https_connect"
                    and attributes.get("server.address") == _SYNTHETIC_HOST
                    and attributes.get("server.port") in (443, "443")
                )
                self.conversation_join = self.conversation_join and (
                    isinstance(self.expected_conversation_id, str)
                    and attributes.get("conversation.id")
                    == self.expected_conversation_id
                )
                if (
                    self.network_event_latency_ms is None
                    and self.command_started_at is not None
                ):
                    self.network_event_latency_ms = (
                        time.monotonic() - self.command_started_at
                    ) * 1000

    def snapshot(self) -> dict[str, int | bool | float | None]:
        with self.lock:
            return {
                "request_count": self.request_count,
                "network_event_count": self.network_event_count,
                "other_event_count": self.other_event_count,
                "parse_error_count": self.parse_error_count,
                "execution_id_count": self.execution_id_count,
                "raw_capable_event_count": self.raw_capable_event_count,
                "context_matches_fixture": (
                    self.context_matches_fixture and self.network_event_count > 0
                ),
                "conversation_join": (
                    self.conversation_join and self.network_event_count > 0
                ),
                "latency_ms": self.network_event_latency_ms,
            }


def run_codex_network_live_probe(
    codex_bin: str = "codex",
    *,
    repeats: int = 3,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run fixed synthetic turns and decline any managed-network approval."""
    if not 1 <= repeats <= 20:
        raise CodexNetworkLiveError("repeats must be between 1 and 20")
    if not 5.0 <= timeout_seconds <= 120.0:
        raise CodexNetworkLiveError("timeout_seconds must be between 5 and 120")
    codex_version = _read_codex_version(codex_bin, timeout_seconds)
    observations = [
        _run_single_observation(codex_bin, timeout_seconds=timeout_seconds)
        for _ in range(repeats)
    ]
    latencies = sorted(
        observation.approval_latency_ms
        for observation in observations
        if observation.approval_latency_ms is not None
    )
    otel_latencies = sorted(
        observation.otel_latency_ms
        for observation in observations
        if observation.otel_latency_ms is not None
    )
    supported_count = sum(
        observation.network_approval_count == 1
        and observation.general_approval_count == 0
        and observation.exact_item_id_join
        and observation.context_matches_fixture
        and observation.turn_completed
        for observation in observations
    )
    otel_supported_count = sum(
        observation.otel_network_event_count == 1
        and observation.otel_parse_error_count == 0
        and observation.otel_context_matches_fixture
        and observation.otel_conversation_join
        and observation.turn_completed
        for observation in observations
    )
    otel_exact_join_count = sum(
        observation.otel_execution_id_count == 1 for observation in observations
    )
    otel_unfiltered_event_count = sum(
        observation.otel_other_event_count for observation in observations
    )
    otel_raw_capable_event_count = sum(
        observation.otel_raw_capable_event_count for observation in observations
    )
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "runner_version": RUNNER_VERSION,
        "codex": {"version": codex_version},
        "execution": {
            "case_id": SYNTHETIC_CASE_ID,
            "repeats": repeats,
            "mock_model_scope": "loopback_only",
            "external_model_request_count": 0,
            "network_policy": "empty_allowlist",
            "approval_decision": "decline",
            "production_policy_connected": False,
            "plugin_hooks_connected": False,
            "otel_scope": "loopback_only",
            "otel_raw_batches_stored": False,
        },
        "observations": {
            "completed_count": sum(item.turn_completed for item in observations),
            "command_item_count": sum(item.command_item_count for item in observations),
            "network_approval_count": sum(
                item.network_approval_count for item in observations
            ),
            "general_approval_count": sum(
                item.general_approval_count for item in observations
            ),
            "exact_join_count": sum(item.exact_item_id_join for item in observations),
            "context_match_count": sum(
                item.context_matches_fixture for item in observations
            ),
            "mock_request_count": sum(item.mock_request_count for item in observations),
            "supported_count": supported_count,
            "approval_latency_ms": {
                "sample_count": len(latencies),
                "p50": _percentile(latencies, 0.50),
                "p95": _percentile(latencies, 0.95),
            },
            "otel": {
                "request_count": sum(item.otel_request_count for item in observations),
                "network_event_count": sum(
                    item.otel_network_event_count for item in observations
                ),
                "other_event_count": sum(
                    item.otel_other_event_count for item in observations
                ),
                "parse_error_count": sum(
                    item.otel_parse_error_count for item in observations
                ),
                "execution_id_count": sum(
                    item.otel_execution_id_count for item in observations
                ),
                "exact_tool_join_count": otel_exact_join_count,
                "raw_capable_event_count": otel_raw_capable_event_count,
                "context_match_count": sum(
                    item.otel_context_matches_fixture for item in observations
                ),
                "conversation_join_count": sum(
                    item.otel_conversation_join for item in observations
                ),
                "supported_count": otel_supported_count,
                "latency_ms": {
                    "sample_count": len(otel_latencies),
                    "p50": _percentile(otel_latencies, 0.50),
                    "p95": _percentile(otel_latencies, 0.95),
                },
            },
        },
    }
    privacy_violations = _privacy_violations(report)
    report["privacy"] = {
        "raw_value_exposure_count": len(privacy_violations),
        "violation_paths": privacy_violations,
        "request_bodies_stored": False,
        "response_bodies_stored": False,
        "subprocess_output_stored": False,
        "otel_batches_stored": False,
        "otel_unfiltered_event_count": otel_unfiltered_event_count,
        "otel_raw_capable_event_count": otel_raw_capable_event_count,
        "otel_value_free_transport": otel_unfiltered_event_count == 0,
        "protected_values_used": False,
    }
    report["summary"] = {
        "live_contract_passed": (
            otel_supported_count == repeats
            and len(otel_latencies) == repeats
            and not privacy_violations
        ),
        "managed_network_approval_supported": supported_count == repeats,
        "otel_observer_supported": otel_supported_count == repeats,
        "production_observer_eligible": (
            otel_supported_count == repeats
            and otel_exact_join_count == repeats
            and otel_unfiltered_event_count == 0
            and not privacy_violations
        ),
        "unsupported_reason": (
            None
            if otel_supported_count == repeats
            else "network_policy_otel_event_not_observed"
        ),
        "production_behavior_changed": False,
    }
    return report


def render_codex_network_live_report(report: dict[str, Any]) -> str:
    execution = report["execution"]
    observations = report["observations"]
    latency = observations["approval_latency_ms"]
    otel = observations["otel"]
    otel_latency = otel["latency_ms"]
    return "\n".join(
        (
            f"Codex version={report['codex']['version']}",
            (
                f"case={execution['case_id']} repeats={execution['repeats']} "
                "model=loopback_only decision=decline"
            ),
            (
                f"completed={observations['completed_count']} "
                f"command_items={observations['command_item_count']} "
                f"network_approvals={observations['network_approval_count']}"
            ),
            (
                f"exact_joins={observations['exact_join_count']} "
                f"context_matches={observations['context_match_count']} "
                f"supported={observations['supported_count']}"
            ),
            (
                f"approval_latency samples={latency['sample_count']} "
                f"p50={_format_ms(latency['p50'])} p95={_format_ms(latency['p95'])}"
            ),
            (
                f"otel_network_events={otel['network_event_count']} "
                f"conversation_joins={otel['conversation_join_count']} "
                f"supported={otel['supported_count']}"
            ),
            (
                f"otel_exact_tool_joins={otel['exact_tool_join_count']} "
                f"unfiltered_events={otel['other_event_count']} "
                f"raw_capable_events={otel['raw_capable_event_count']}"
            ),
            (
                f"otel_latency samples={otel_latency['sample_count']} "
                f"p50={_format_ms(otel_latency['p50'])} "
                f"p95={_format_ms(otel_latency['p95'])}"
            ),
            (
                "privacy raw_value_exposure_count="
                f"{report['privacy']['raw_value_exposure_count']}"
            ),
            (
                "OTel evaluation transport="
                f"{'PASS' if report['summary']['live_contract_passed'] else 'UNSUPPORTED'}"
            ),
            (
                "production observer="
                f"{'ELIGIBLE' if report['summary']['production_observer_eligible'] else 'INELIGIBLE'}"
            ),
        )
    )


def _run_single_observation(
    codex_bin: str,
    *,
    timeout_seconds: float,
) -> LiveObservation:
    with tempfile.TemporaryDirectory(prefix="tooluseproxy-network-live-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        codex_home = root / "codex-home"
        workspace.mkdir()
        codex_home.mkdir()
        state = _MockState(workspace=workspace)
        otel_state = _OtelState()
        server = _start_mock_server(state)
        otel_server = _start_otel_server(otel_state)
        try:
            return _run_app_server_turn(
                codex_bin,
                workspace=workspace,
                codex_home=codex_home,
                model_base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
                otel_endpoint=f"http://127.0.0.1:{otel_server.server_address[1]}/v1/logs",
                mock_state=state,
                otel_state=otel_state,
                timeout_seconds=timeout_seconds,
            )
        finally:
            server.shutdown()
            server.server_close()
            otel_server.shutdown()
            otel_server.server_close()


def _start_mock_server(state: _MockState) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if content_length < 0 or content_length > 4 * 1024 * 1024:
                self.send_error(413)
                return
            self.rfile.read(content_length)
            body = state.next_response()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _start_otel_server(state: _OtelState) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if content_length < 0 or content_length > 4 * 1024 * 1024:
                self.send_error(413)
                return
            state.observe(self.rfile.read(content_length))
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _run_app_server_turn(
    codex_bin: str,
    *,
    workspace: Path,
    codex_home: Path,
    model_base_url: str,
    otel_endpoint: str,
    mock_state: _MockState,
    otel_state: _OtelState,
    timeout_seconds: float,
) -> LiveObservation:
    argv = [
        codex_bin,
        "app-server",
        "-c",
        'model_provider="tooluseproxy_mock"',
        "-c",
        'model="tooluseproxy-synthetic"',
        "-c",
        'model_providers.tooluseproxy_mock.name="ToolUseProxy synthetic mock"',
        "-c",
        f'model_providers.tooluseproxy_mock.base_url="{model_base_url}"',
        "-c",
        'model_providers.tooluseproxy_mock.wire_api="responses"',
        "-c",
        "model_providers.tooluseproxy_mock.request_max_retries=0",
        "-c",
        "model_providers.tooluseproxy_mock.stream_max_retries=0",
        "-c",
        'approval_policy="on-request"',
        "-c",
        "features.network_proxy.enabled=true",
        "-c",
        "features.network_proxy.domains={}",
        "-c",
        "features.network_proxy.allow_local_binding=false",
        "-c",
        "features.network_proxy.allow_upstream_proxy=false",
        "-c",
        "sandbox_workspace_write.network_access=true",
        "-c",
        'web_search="disabled"',
        "-c",
        (
            "otel.exporter={ otlp-http = { endpoint = "
            f'"{otel_endpoint}"'
            ', protocol = "json" } }'
        ),
        "-c",
        "otel.log_user_prompt=false",
        "-c",
        'otel.trace_exporter="none"',
        "-c",
        'otel.metrics_exporter="none"',
        "-c",
        "analytics.enabled=false",
        "--listen",
        "stdio://",
    ]
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "CODEX_HOME": str(codex_home)},
            start_new_session=True,
        )
    except OSError as error:
        raise CodexNetworkLiveError("failed to launch Codex app-server") from error
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise CodexNetworkLiveError("Codex app-server stdio is unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    command_item_ids: set[str] = set()
    approval_item_ids: list[str] = []
    command_started_at: dict[str, float] = {}
    approval_latencies: list[float] = []
    network_approval_count = 0
    general_approval_count = 0
    context_matches_fixture = True
    turn_completed = False
    stderr_bytes = 0
    phase = "initialize"

    def send(payload: dict[str, Any]) -> None:
        try:
            process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            process.stdin.flush()
        except OSError as error:
            raise CodexNetworkLiveError("Codex app-server request write failed") from error

    send(
        {
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "tooluseproxy-network-probe",
                    "version": "1",
                },
                "capabilities": {"experimentalApi": True},
            },
        }
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline and not turn_completed:
            events = selector.select(timeout=max(0.0, deadline - time.monotonic()))
            if not events:
                break
            for key, _ in events:
                line = key.fileobj.readline()
                if not line:
                    continue
                if len(line.encode("utf-8")) > _MAX_LINE_BYTES:
                    raise CodexNetworkLiveError("Codex app-server line exceeded limit")
                if key.data == "stderr":
                    stderr_bytes += len(line.encode("utf-8"))
                    if stderr_bytes > _MAX_STDERR_BYTES:
                        raise CodexNetworkLiveError(
                            "Codex app-server stderr exceeded limit"
                        )
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as error:
                    raise CodexNetworkLiveError(
                        "Codex app-server emitted invalid JSON"
                    ) from error
                if not isinstance(message, dict):
                    raise CodexNetworkLiveError(
                        "Codex app-server message must be an object"
                    )
                if message.get("id") == 1 and phase == "initialize":
                    _require_success(message, "initialize")
                    send({"method": "initialized", "params": {}})
                    send(
                        {
                            "id": 2,
                            "method": "thread/start",
                            "params": {
                                "model": "tooluseproxy-synthetic",
                                "modelProvider": "tooluseproxy_mock",
                                "cwd": str(workspace),
                                "approvalPolicy": "on-request",
                                "sandbox": "workspace-write",
                                "ephemeral": True,
                                "baseInstructions": "Use only the synthetic tool call.",
                                "developerInstructions": "Do not inspect files or alter the call.",
                            },
                        }
                    )
                    phase = "thread"
                    continue
                if message.get("id") == 2 and phase == "thread":
                    result = _require_success(message, "thread start")
                    thread_id = result.get("thread", {}).get("id")
                    if not isinstance(thread_id, str):
                        raise CodexNetworkLiveError("thread start omitted thread id")
                    send(
                        {
                            "id": 3,
                            "method": "turn/start",
                            "params": {
                                "threadId": thread_id,
                                "input": [
                                    {"type": "text", "text": "Run the fixed synthetic call."}
                                ],
                            },
                        }
                    )
                    phase = "turn"
                    continue
                if message.get("id") == 3 and "error" in message:
                    raise CodexNetworkLiveError("turn start failed")
                method = message.get("method")
                if method == "item/started":
                    item = message.get("params", {}).get("item", {})
                    item_id = item.get("id") if isinstance(item, dict) else None
                    if (
                        isinstance(item, dict)
                        and item.get("type") == "commandExecution"
                        and isinstance(item_id, str)
                    ):
                        command_item_ids.add(item_id)
                        command_started_at[item_id] = time.monotonic()
                        if phase == "turn":
                            otel_state.set_turn_context(
                                thread_id,
                                command_started_at[item_id],
                            )
                    continue
                if method == "item/commandExecution/requestApproval":
                    params = message.get("params", {})
                    context = (
                        params.get("networkApprovalContext")
                        if isinstance(params, dict)
                        else None
                    )
                    if isinstance(context, dict):
                        network_approval_count += 1
                        item_id = params.get("itemId")
                        if isinstance(item_id, str):
                            approval_item_ids.append(item_id)
                            started_at = command_started_at.get(item_id)
                            if started_at is not None:
                                approval_latencies.append(
                                    (time.monotonic() - started_at) * 1000
                                )
                        context_matches_fixture = context_matches_fixture and (
                            context.get("host") == _SYNTHETIC_HOST
                            and context.get("protocol") == "https"
                        )
                    else:
                        general_approval_count += 1
                    request_id = message.get("id")
                    if not isinstance(request_id, (int, str)):
                        raise CodexNetworkLiveError("approval request omitted request id")
                    send({"id": request_id, "result": {"decision": "decline"}})
                    continue
                if method == "turn/completed":
                    turn_completed = True
    finally:
        selector.close()
        try:
            process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
    if not turn_completed:
        raise CodexNetworkLiveError("Codex synthetic turn timed out")
    exact_join = bool(approval_item_ids) and all(
        item_id in command_item_ids for item_id in approval_item_ids
    )
    otel_snapshot = otel_state.snapshot()
    return LiveObservation(
        command_item_count=len(command_item_ids),
        network_approval_count=network_approval_count,
        general_approval_count=general_approval_count,
        exact_item_id_join=exact_join,
        context_matches_fixture=(
            context_matches_fixture and network_approval_count > 0
        ),
        approval_latency_ms=(
            approval_latencies[0] if len(approval_latencies) == 1 else None
        ),
        turn_completed=turn_completed,
        mock_request_count=mock_state.request_count,
        otel_request_count=int(otel_snapshot["request_count"]),
        otel_network_event_count=int(otel_snapshot["network_event_count"]),
        otel_other_event_count=int(otel_snapshot["other_event_count"]),
        otel_parse_error_count=int(otel_snapshot["parse_error_count"]),
        otel_execution_id_count=int(otel_snapshot["execution_id_count"]),
        otel_raw_capable_event_count=int(
            otel_snapshot["raw_capable_event_count"]
        ),
        otel_context_matches_fixture=bool(
            otel_snapshot["context_matches_fixture"]
        ),
        otel_conversation_join=bool(otel_snapshot["conversation_join"]),
        otel_latency_ms=(
            float(otel_snapshot["latency_ms"])
            if otel_snapshot["latency_ms"] is not None
            else None
        ),
    )


def _function_call_item(workspace: Path) -> dict[str, Any]:
    arguments = json.dumps(
        {
            "cmd": (
                "/usr/bin/curl --max-time 2 --silent --show-error "
                f"--output /dev/null {_SYNTHETIC_URL}"
            ),
            "workdir": str(workspace),
            "yield_time_ms": 5000,
            "max_output_tokens": 1000,
        },
        separators=(",", ":"),
    )
    return {
        "id": "fc_mock",
        "type": "function_call",
        "status": "completed",
        "arguments": arguments,
        "call_id": "call_mock",
        "name": "exec_command",
    }


def _function_call_events(item: dict[str, Any], request_number: int) -> list[dict[str, Any]]:
    pending = {**item, "status": "in_progress", "arguments": ""}
    arguments = item["arguments"]
    return [
        {
            "type": "response.created",
            "response": _response([], request_number, status="in_progress"),
        },
        {"type": "response.output_item.added", "output_index": 0, "item": pending},
        {
            "type": "response.function_call_arguments.delta",
            "item_id": item["id"],
            "output_index": 0,
            "delta": arguments,
        },
        {
            "type": "response.function_call_arguments.done",
            "item_id": item["id"],
            "output_index": 0,
            "arguments": arguments,
        },
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {
            "type": "response.completed",
            "response": _response([item], request_number),
        },
    ]


def _message_item() -> dict[str, Any]:
    return {
        "id": "msg_mock",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [
            {
                "type": "output_text",
                "text": "synthetic complete",
                "annotations": [],
                "logprobs": [],
            }
        ],
    }


def _response(
    output: list[dict[str, Any]],
    request_number: int,
    *,
    status: str = "completed",
) -> dict[str, Any]:
    return {
        "id": f"resp_mock_{request_number}",
        "object": "response",
        "created_at": 0,
        "status": status,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
        "model": "tooluseproxy-synthetic",
        "output": output,
        "parallel_tool_calls": False,
        "previous_response_id": None,
        "reasoning": {"effort": None, "summary": None},
        "store": False,
        "temperature": None,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_p": None,
        "truncation": "disabled",
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
        "metadata": {},
    }


def _read_codex_version(codex_bin: str, timeout_seconds: float) -> str:
    try:
        completed = subprocess.run(
            [codex_bin, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        raise CodexNetworkLiveError("Codex CLI was not found") from None
    except subprocess.TimeoutExpired:
        raise CodexNetworkLiveError("Codex version probe timed out") from None
    if completed.returncode != 0:
        raise CodexNetworkLiveError("Codex version probe failed")
    match = _VERSION_PATTERN.fullmatch(completed.stdout.strip())
    if match is None:
        raise CodexNetworkLiveError("Codex version output is unsupported")
    return match.group(1)


def _otel_log_records(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise TypeError("OTLP document must be an object")
    resource_logs = document.get("resourceLogs")
    if not isinstance(resource_logs, list):
        raise ValueError("OTLP document omitted resourceLogs")
    records: list[dict[str, Any]] = []
    for resource_log in resource_logs:
        if not isinstance(resource_log, dict):
            raise TypeError("OTLP resource log must be an object")
        scope_logs = resource_log.get("scopeLogs", [])
        if not isinstance(scope_logs, list):
            raise TypeError("OTLP scopeLogs must be an array")
        for scope_log in scope_logs:
            if not isinstance(scope_log, dict):
                raise TypeError("OTLP scope log must be an object")
            log_records = scope_log.get("logRecords", [])
            if not isinstance(log_records, list):
                raise TypeError("OTLP logRecords must be an array")
            for record in log_records:
                if not isinstance(record, dict):
                    raise TypeError("OTLP log record must be an object")
                records.append(record)
    return records


def _otel_attributes(record: dict[str, Any]) -> dict[str, str | int | bool]:
    raw_attributes = record.get("attributes", [])
    if not isinstance(raw_attributes, list):
        raise TypeError("OTLP attributes must be an array")
    attributes: dict[str, str | int | bool] = {}
    for attribute in raw_attributes:
        if not isinstance(attribute, dict):
            raise TypeError("OTLP attribute must be an object")
        key = attribute.get("key")
        value = attribute.get("value")
        if not isinstance(key, str) or not isinstance(value, dict):
            raise TypeError("OTLP attribute key/value is invalid")
        supported = [
            value.get("stringValue"),
            value.get("intValue"),
            value.get("boolValue"),
        ]
        present = [item for item in supported if isinstance(item, (str, int, bool))]
        if len(present) == 1:
            attributes[key] = present[0]
    return attributes


def _require_success(message: dict[str, Any], stage: str) -> dict[str, Any]:
    result = message.get("result")
    if "error" in message or not isinstance(result, dict):
        raise CodexNetworkLiveError(f"Codex app-server {stage} failed")
    return result


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 3)
    return round(statistics.quantiles(values, n=100, method="inclusive")[int(percentile * 100) - 1], 3)


def _format_ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}ms"


def _privacy_violations(report: dict[str, Any]) -> list[str]:
    forbidden = {
        "argv",
        "command",
        "credential",
        "dns_label",
        "host",
        "payload",
        "protected_value",
        "query",
        "raw_value",
        "stderr",
        "stdout",
        "url",
    }
    violations: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                nested_path = f"{path}.{key}"
                if key in forbidden:
                    violations.append(nested_path)
                visit(nested, nested_path)
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                visit(nested, f"{path}[{index}]")

    visit(report, "$")
    return sorted(violations)
