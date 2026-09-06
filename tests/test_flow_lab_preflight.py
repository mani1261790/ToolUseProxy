from __future__ import annotations

import copy
import io
import json
import subprocess
import tarfile

import pytest

from hook_monitor.evaluation.flow_lab import preflight as lab


IMAGE = "sha256:" + "a" * 64


def profile() -> dict:
    return {
        "Image": IMAGE,
        "Config": {"User": "65532:65532", "Labels": {lab.LABEL: "true"}},
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 32, "Memory": lab.MEMORY_BYTES, "MemorySwap": lab.MEMORY_BYTES,
            "NanoCpus": 1_000_000_000, "IpcMode": "none",
            "Tmpfs": {"/work": lab.TMPFS.split(":", 1)[1]},
        },
        "Mounts": [], "State": {"ExitCode": 0},
    }


def test_valid_profile_and_fixed_invocation() -> None:
    lab.validate_profile(profile(), IMAGE)
    argv = lab.create_argv(IMAGE, "tup-lab-" + "b" * 32)
    assert "--network" in argv and "none" in argv
    assert "--read-only" in argv
    assert not {"--volume", "--mount", "--env-file", "--privileged"}.intersection(argv)
    assert argv[-4:] == ["-I", "-B", "-c", lab.PROBE]


@pytest.mark.parametrize("key,value", [
    ("NetworkMode", "host"), ("ReadonlyRootfs", False), ("Privileged", True),
    ("CapDrop", []), ("CapAdd", ["NET_ADMIN"]), ("SecurityOpt", []),
    ("SecurityOpt", ["no-new-privileges:true", "seccomp=unconfined"]),
    ("PidsLimit", -1), ("Memory", 0), ("MemorySwap", -1), ("NanoCpus", 0),
    ("IpcMode", "host"), ("PidMode", "host"), ("UTSMode", "host"),
    ("Binds", ["/host:/host"]), ("Devices", [{"PathOnHost": "/dev/test"}]),
    ("VolumesFrom", ["other"]), ("PortBindings", {"8000/tcp": []}),
    ("ExtraHosts", ["host.docker.internal:host-gateway"]), ("Tmpfs", {}),
])
def test_unsafe_profile_is_rejected(key, value) -> None:
    item = profile()
    item["HostConfig"][key] = value
    with pytest.raises(lab.LabError, match="unsafe_container_profile"):
        lab.validate_profile(item, IMAGE)


@pytest.mark.parametrize("key,value", [
    ("Image", "different"), ("Mounts", [{"Source": "/host"}]),
    ("Config", {"User": "0", "Labels": {lab.LABEL: "true"}}),
])
def test_wrong_image_user_or_mount_is_rejected(key, value) -> None:
    item = profile()
    item[key] = value
    with pytest.raises(lab.LabError):
        lab.validate_profile(item, IMAGE)


@pytest.mark.parametrize("item", [None, [], {"Config": None}, {"HostConfig": None}])
def test_malformed_profile_is_rejected(item) -> None:
    with pytest.raises(lab.LabError, match="invalid_container_response"):
        lab.validate_profile(item, IMAGE)


@pytest.mark.parametrize("image,name", [
    ("python:latest", "tup-lab-" + "b" * 32),
    (IMAGE, "--privileged"), (IMAGE, "tup-lab-../../test"),
])
def test_only_exact_resource_identities_are_accepted(image, name) -> None:
    with pytest.raises(lab.LabError):
        lab.create_argv(image, name)


def test_context_contains_only_tracked_package_source(tmp_path, monkeypatch) -> None:
    source = tmp_path / "hook_monitor/runtime/runner.py"
    source.parent.mkdir(parents=True)
    source.write_text("# synthetic detector fixture\n")
    (tmp_path / "protected_sources.json").write_text("NEVER_COPY_USER_MANIFEST")
    (tmp_path / "auth.json").write_text("NEVER_COPY_CREDENTIAL")
    (source.parent / "untracked.py").write_text("NEVER_COPY_UNTRACKED")
    monkeypatch.setattr(lab, "command", lambda *a, **kw: b"hook_monitor/runtime/runner.py\0")
    first = lab.build_context(tmp_path)
    assert first == lab.build_context(tmp_path)
    assert b"NEVER_COPY" not in first
    with tarfile.open(fileobj=io.BytesIO(first)) as archive:
        assert set(archive.getnames()) == {
            "Dockerfile", "fixtures/protected.txt", "fixtures/policy.json",
            "fixtures/protected_sources.json",
            "code/hook_monitor/runtime/runner.py",
        }


def test_context_rejects_source_symlink(tmp_path, monkeypatch) -> None:
    source = tmp_path / "hook_monitor/runtime/runner.py"
    source.parent.mkdir(parents=True)
    other = tmp_path / "private.py"
    other.write_text("private")
    source.symlink_to(other)
    monkeypatch.setattr(lab, "command", lambda *a, **kw: b"hook_monitor/runtime/runner.py\0")
    with pytest.raises(lab.LabError, match="source_symlink"):
        lab.build_context(tmp_path)


def test_context_rejects_parent_symlink(tmp_path, monkeypatch) -> None:
    other = tmp_path / "other"
    other.mkdir()
    (tmp_path / "hook_monitor").symlink_to(other, target_is_directory=True)
    monkeypatch.setattr(lab, "command", lambda *a, **kw: b"hook_monitor/runtime/runner.py\0")
    with pytest.raises(lab.LabError, match="source_symlink"):
        lab.build_context(tmp_path)


def test_context_requires_detector(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(lab, "command", lambda *a, **kw: b"")
    with pytest.raises(lab.LabError, match="detector_source_missing"):
        lab.build_context(tmp_path)


def test_probe_always_cleans_its_exact_container_on_timeout(monkeypatch) -> None:
    calls = []

    def command(argv, **kw):
        calls.append(argv)
        if argv[1] == "start":
            raise lab.LabError("command_timeout")
        return b""

    monkeypatch.setattr(lab, "command", command)
    monkeypatch.setattr(lab, "document", lambda argv: [profile()])
    with pytest.raises(lab.LabError, match="command_timeout"):
        lab.check_isolation(IMAGE)
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ["docker", "rm", "--force", name]
    assert "prune" not in str(calls)


def test_probe_does_not_start_unsafe_container(monkeypatch) -> None:
    calls = []
    item = profile()
    item["HostConfig"]["Privileged"] = True
    monkeypatch.setattr(lab, "command", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(lab, "document", lambda argv: [item])
    with pytest.raises(lab.LabError, match="unsafe_container_profile"):
        lab.check_isolation(IMAGE)
    assert all(call[1] != "start" for call in calls)
    assert calls[-1][1] == "rm"


def test_probe_result_does_not_claim_network_or_native_hook_evidence(monkeypatch) -> None:
    checks = dict.fromkeys([
        "unprivileged_uid", "detector_readonly", "policy_readonly", "source_readonly",
        "no_host_mounts_visible", "no_docker_socket", "no_model_credentials",
        "scratch_writable",
    ], True)
    monkeypatch.setattr(lab, "command", lambda argv, **kw: json.dumps(checks).encode())
    monkeypatch.setattr(lab, "document", lambda argv: [copy.deepcopy(profile())])
    result = lab.check_isolation(IMAGE)
    assert result["status"] == "offline_isolation_verified"
    assert result["receiver_delivery"] == "not_tested"
    assert result["native_codex_hook_delivery"] == "not_tested"
    assert result["model_execution"] is False


def test_process_error_does_not_disclose_stderr(monkeypatch) -> None:
    monkeypatch.setattr(
        lab.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 1, b"PRIVATE", b"PRIVATE"),
    )
    with pytest.raises(lab.LabError, match="^command_failed$"):
        lab.command(["docker", "inspect"])


def test_command_timeout_is_closed_error(monkeypatch) -> None:
    def fail(*a, **kw):
        raise subprocess.TimeoutExpired("PRIVATE", 1, output="PRIVATE")
    monkeypatch.setattr(lab.subprocess, "run", fail)
    with pytest.raises(lab.LabError, match="^command_timeout$"):
        lab.command(["docker", "inspect"])
