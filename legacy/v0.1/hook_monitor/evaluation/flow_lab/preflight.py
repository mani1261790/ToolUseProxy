"""Build a source-only lab image and verify an isolated, offline execution profile.

No model calls, user configuration, source registration, or real-use DB access.
Native Codex Hook delivery is deliberately NOT attested by this check.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import uuid


BASE_IMAGE = "python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217"
LABEL = "org.tooluseproxy.flow-lab"
MAX_CONTEXT_BYTES = 8 * 1024 * 1024
MEMORY_BYTES = 128 * 1024 * 1024
TMPFS = "/work:rw,nosuid,nodev,noexec,size=16777216,mode=0700,uid=65532,gid=65532"
DOCKERFILE = f"""FROM {BASE_IMAGE}
COPY code/ /opt/tooluseproxy/
COPY fixtures/ /opt/flow-lab/
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
USER 65532:65532
"""
PROBE = """import json, os
from pathlib import Path
checks = {}
checks['unprivileged_uid'] = os.getuid() == 65532
for key, name in (
    ('detector_readonly', '/opt/tooluseproxy/hook_monitor/runtime/runner.py'),
    ('policy_readonly', '/opt/flow-lab/policy.json'),
    ('source_readonly', '/opt/flow-lab/protected.txt'),
):
    target = Path(name)
    checks[key] = False
    if target.is_file():
        try:
            with target.open('ab') as handle:
                handle.write(b'')
        except OSError:
            checks[key] = True
checks['no_host_mounts_visible'] = not Path('/host').exists()
checks['no_docker_socket'] = not Path('/var/run/docker.sock').exists()
checks['no_model_credentials'] = not any(
    k in os.environ for k in ('OPENAI_API_KEY', 'CODEX_HOME', 'GH_TOKEN', 'GITHUB_TOKEN')
)
Path('/work/probe.txt').write_text('synthetic-only')
checks['scratch_writable'] = Path('/work/probe.txt').read_text() == 'synthetic-only'
print(json.dumps(checks, sort_keys=True))
"""


class LabError(RuntimeError):
    """Closed diagnostic code, never raw engine/model output."""


def command(argv: list[str], *, timeout: float = 15, data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            argv, input=data, capture_output=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise LabError("executable_unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise LabError("command_timeout") from exc
    except OSError as exc:
        raise LabError("command_failed") from exc
    if completed.returncode != 0:
        raise LabError("command_failed")
    if len(completed.stdout) > 4 * 1024 * 1024:
        raise LabError("command_output_limit")
    return completed.stdout


def document(argv: list[str]) -> object:
    try:
        return json.loads(command(argv))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabError("invalid_engine_response") from exc


def build_context(repository: Path) -> bytes:
    """Read only tracked Python source in two explicit package directories.

    Never tar the workspace or use a broad Docker build context. In particular,
    the user's root protected_sources.json cannot enter this archive.
    """
    repository = repository.resolve(strict=True)
    names = command([
        "git", "-C", str(repository), "ls-files", "-z", "--",
        "hook_monitor", "tooluseproxy",
    ]).decode("utf-8").split("\0")
    files: dict[str, bytes] = {
        "Dockerfile": DOCKERFILE.encode(),
        "fixtures/protected.txt": b"FLOW_LAB_SYNTHETIC_SOURCE_ONLY\n",
        "fixtures/policy.json": b'{"synthetic_only":true,"network":"none"}\n',
        "fixtures/protected_sources.json": json.dumps({
            "schema_version": 2, "sources": [{
                "id": "synthetic-source", "path": "protected.txt",
                "type": "unpublished_impl", "sensitivity": "high",
                "policy_tags": ["no_external"],
            }],
        }, sort_keys=True).encode(),
    }
    for name in names:
        if not name or not name.endswith(".py"):
            continue
        parts = Path(name).parts
        if parts[0] not in {"hook_monitor", "tooluseproxy"} or ".." in parts:
            raise LabError("invalid_source_path")
        if name.startswith("hook_monitor/evaluation/"):
            continue
        path = repository / name
        if any(p.is_symlink() for p in (path, *path.parents) if p != repository):
            raise LabError("source_symlink")
        if path.resolve(strict=True) != path or not path.is_file():
            raise LabError("invalid_source_path")
        before = path.stat()
        if before.st_size > 2 * 1024 * 1024:
            raise LabError("source_size_limit")
        content = path.read_bytes()
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise LabError("source_changed")
        files["code/" + name] = content
        if sum(map(len, files.values())) > MAX_CONTEXT_BYTES:
            raise LabError("source_size_limit")
    if "code/hook_monitor/runtime/runner.py" not in files:
        raise LabError("detector_source_missing")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o444
            entry.size = len(data)
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def build_image(repository: Path, *, docker: str = "docker", context: bytes | None = None) -> str:
    context = build_context(repository) if context is None else context
    digest = hashlib.sha256(context).hexdigest()
    tag = f"tooluseproxy-flow-lab:{digest[:24]}"
    command([
        docker, "build", "--network=none", "--pull=false", "--label", f"{LABEL}=true",
        "--tag", tag, "-",
    ], data=context, timeout=120)
    result = document([docker, "image", "inspect", tag])
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise LabError("invalid_image_response")
    image_id = result[0].get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise LabError("invalid_image_identity")
    return image_id


def create_argv(image_id: str, name: str, *, docker: str = "docker") -> list[str]:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise LabError("invalid_image_identity")
    if not re.fullmatch(r"tup-lab-[a-f0-9]{32}", name):
        raise LabError("invalid_container_identity")
    return [
        docker, "create", "--name", name, "--label", f"{LABEL}=true",
        "--network", "none", "--read-only", "--user", "65532:65532",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "32", "--memory", str(MEMORY_BYTES),
        "--memory-swap", str(MEMORY_BYTES), "--cpus", "1", "--ipc", "none",
        "--tmpfs", TMPFS, "--workdir", "/work", "--entrypoint", "python",
        image_id, "-I", "-B", "-c", PROBE,
    ]


def validate_profile(item: object, image_id: str, *, network: str = "none") -> None:
    if network != "none" and not re.fullmatch(r"tup-lab-net-[a-f0-9]{32}", network):
        raise LabError("invalid_network_identity")
    if not isinstance(item, dict):
        raise LabError("invalid_container_response")
    host = item.get("HostConfig", {})
    config = item.get("Config", {})
    if not isinstance(host, dict) or not isinstance(config, dict):
        raise LabError("invalid_container_response")
    labels = config.get("Labels")
    security = host.get("SecurityOpt")
    if not isinstance(labels, dict) or not isinstance(security, list):
        raise LabError("invalid_container_response")
    checks = [
        item.get("Image") == image_id,
        config.get("User") == "65532:65532",
        labels.get(LABEL) == "true",
        host.get("NetworkMode") == network,
        host.get("ReadonlyRootfs") is True,
        not host.get("Privileged"),
        host.get("CapDrop") == ["ALL"],
        not host.get("CapAdd"),
        security == ["no-new-privileges:true"],
        host.get("PidsLimit") == 32,
        host.get("Memory") == MEMORY_BYTES,
        host.get("MemorySwap") == MEMORY_BYTES,
        host.get("NanoCpus") == 1_000_000_000,
        host.get("IpcMode") == "none",
        not host.get("PidMode"),
        not host.get("UTSMode"),
        not host.get("Binds"),
        not host.get("VolumesFrom"),
        not host.get("Devices"),
        not host.get("PortBindings"),
        not host.get("ExtraHosts"),
        not item.get("Mounts"),
        host.get("Tmpfs") == {"/work": TMPFS.split(":", 1)[1]},
    ]
    if not all(checks):
        raise LabError("unsafe_container_profile")


def check_isolation(image_id: str, *, docker: str = "docker") -> dict[str, object]:
    name = "tup-lab-" + uuid.uuid4().hex
    created = False
    try:
        command(create_argv(image_id, name, docker=docker))
        created = True
        before = document([docker, "inspect", name])
        if not isinstance(before, list) or len(before) != 1:
            raise LabError("invalid_container_response")
        validate_profile(before[0], image_id)
        raw = command([docker, "start", "--attach", name], timeout=20)
        try:
            checks = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LabError("invalid_probe_response") from exc
        expected = {
            "unprivileged_uid", "detector_readonly", "policy_readonly", "source_readonly",
            "no_host_mounts_visible", "no_docker_socket", "no_model_credentials",
            "scratch_writable",
        }
        if not isinstance(checks, dict) or set(checks) != expected:
            raise LabError("invalid_probe_response")
        if any(value is not True for value in checks.values()):
            raise LabError("isolation_probe_failed")
        after = document([docker, "inspect", name])
        if not isinstance(after, list) or len(after) != 1:
            raise LabError("invalid_container_response")
        validate_profile(after[0], image_id)
        if after[0].get("State", {}).get("ExitCode") != 0:
            raise LabError("isolation_probe_failed")
        return {
            "schema_version": 1, "status": "offline_isolation_verified",
            "checks": checks, "network_mode": "none", "host_mount_count": 0,
            "native_codex_hook_delivery": "not_tested",
            "receiver_delivery": "not_tested", "model_execution": False,
        }
    finally:
        if created:
            # Exact randomly named resource created above; never prune shared Docker state.
            command([docker, "rm", "--force", name], timeout=10)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="人工試験用の通信なし隔離環境を確認します")
    parser.add_argument("--repository", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        image_id = build_image(options.repository)
        result = check_isolation(image_id)
    except (LabError, OSError, UnicodeError) as exc:
        code = str(exc) if isinstance(exc, LabError) else "local_input_error"
        print(json.dumps({"status": "not_verified", "reason": code}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
