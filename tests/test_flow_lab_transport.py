from __future__ import annotations

import base64
import json
import shlex

import pytest

from hook_monitor.evaluation.flow_lab import transport as module
from hook_monitor.evaluation.flow_lab.preflight import LABEL, LabError


def network():
    return {
        "Name": "tup-lab-net-" + "a" * 32, "Driver": "bridge", "Internal": True,
        "EnableIPv6": False, "Ingress": False, "Labels": {LABEL: "true"},
        "Options": {module.GATEWAY_OPTION: "isolated", module.MASQUERADE_OPTION: "false"},
    }


@pytest.mark.parametrize("key,value", [
    ("Driver", "host"), ("Internal", False), ("EnableIPv6", True), ("Ingress", True),
    ("Labels", None), ("Options", None), ("Options", {}), ("Labels", {}),
])
def test_unsafe_network_is_rejected(key, value):
    original = network()
    module.validate_network(original, original["Name"])
    with pytest.raises(LabError):
        module.validate_network({**original, key: value}, original["Name"])


def test_fixed_commands_are_synthetic_and_encoding_not_plaintext():
    plain = module.python_command("172.22.0.2", "a" * 32, source="protected")
    encoded = module.python_command("172.22.0.2", "a" * 32, source="protected", encoding="base64")
    assert module.CANARY in plain
    assert module.CANARY not in encoded
    assert base64.b64encode(module.CANARY.encode()).decode() in encoded
    assert shlex.split(plain)[:4] == ["python", "-I", "-B", "-c"]
    with pytest.raises(LabError):
        module.python_command("8.8.8.8", "a" * 32, source="protected")
    with pytest.raises(LabError):
        module.python_command("172.22.0.2", "a" * 32, source="real")


def test_unknown_commands_cannot_reach_sender_or_guard():
    transport = module.FixedTransport("sha256:" + "a" * 64)
    with pytest.raises(LabError, match="unprepared"):
        transport.send("anything")
    with pytest.raises(LabError, match="unprepared"):
        transport.guard("anything", session_id="a" * 32, step_id="b" * 32)


@pytest.mark.parametrize("exit_code,expected", [(0, True), (1, False), (137, False)])
def test_sender_checks_container_exit_not_docker_attach_exit(monkeypatch, exit_code, expected):
    transport = module.FixedTransport("sha256:" + "a" * 64)
    transport.address = "172.22.0.2"
    cmd = transport.prepare("b" * 32, source="public")
    monkeypatch.setattr(transport, "_create", lambda *a, **kw: None)
    monkeypatch.setattr(transport, "check_network", lambda: None)
    monkeypatch.setattr(module, "command", lambda *a, **kw: b"")
    monkeypatch.setattr(transport, "inspect", lambda *a, **kw: {
        "State": {"Running": False, "Status": "exited", "ExitCode": exit_code},
    })
    assert transport.send(cmd) is expected


def test_missing_receiver_does_not_mean_no_leak(monkeypatch):
    transport = module.FixedTransport("sha256:" + "a" * 64)
    monkeypatch.setattr(transport, "inspect", lambda *a, **kw: {"State": {"Running": False}})
    assert transport.delivery("a" * 32) == ("unknown", "unknown")


@pytest.mark.parametrize("record", [
    {"kind": "received", "step_id": "a" * 32, "protected": True, "body_size": 3, "body": "raw"},
    {"kind": "received", "step_id": "a" * 32, "protected": "yes", "body_size": 3},
    {"kind": "received", "step_id": "a" * 32, "protected": False, "body_size": True},
    {"kind": "received", "step_id": "raw-path", "protected": False, "body_size": 3},
])
def test_receiver_raw_or_malformed_fields_rejected(monkeypatch, record):
    transport = module.FixedTransport("sha256:" + "a" * 64)
    monkeypatch.setattr(module, "command", lambda *a, **kw: json.dumps(record).encode())
    with pytest.raises(LabError, match="invalid_receiver_record"):
        transport.records()


def test_duplicate_receipt_is_not_counted(monkeypatch):
    transport = module.FixedTransport("sha256:" + "a" * 64)
    monkeypatch.setattr(transport, "inspect", lambda *a, **kw: {"State": {"Running": True}})
    monkeypatch.setattr(transport, "records", lambda: [{"step_id": "a" * 32}] * 2)
    with pytest.raises(LabError, match="duplicate_receiver"):
        transport.delivery("a" * 32)


def test_cleanup_only_owned_exact_resources(monkeypatch):
    transport = module.FixedTransport("sha256:" + "a" * 64)
    transport.owned = ["tup-lab-" + "b" * 32, "tup-lab-" + "c" * 32]
    owned = list(transport.owned)
    transport.network_created = True
    calls = []
    monkeypatch.setattr(module, "command", lambda args, **kw: calls.append(args))
    transport.close()
    assert calls == [["docker", "rm", "--force", n] for n in reversed(owned)] + [
        ["docker", "network", "rm", transport.network],
    ]
    assert transport.owned == []
