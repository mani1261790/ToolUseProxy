#!/usr/bin/env python3
from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_BUILDER = REPO_ROOT / "scripts" / "build_package.py"
PLUGIN_BUILDER = REPO_ROOT / "scripts" / "build_plugin_bundle.py"
MANIFEST_FILENAME = "release-manifest.json"
CHECKSUM_FILENAME = "SHA256SUMS"
SBOM_SPEC_VERSION = "1.7"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ReleaseCandidateError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build or verify the complete ToolUseProxy release candidate artifact set.",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--outdir", type=Path, help="Create a new candidate directory.")
    action.add_argument("--verify", type=Path, help="Verify an existing candidate directory.")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Refuse to build when the source worktree differs from HEAD.",
    )
    args = parser.parse_args()

    try:
        if args.verify is not None:
            if args.require_clean:
                raise ReleaseCandidateError("--require-clean is only valid while building")
            summary = verify_candidate(args.verify.expanduser().resolve())
        else:
            assert args.outdir is not None
            summary = build_candidate(
                args.outdir.expanduser().resolve(),
                require_clean=args.require_clean,
            )
    except ReleaseCandidateError as error:
        print(f"release candidate: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


def build_candidate(outdir: Path, *, require_clean: bool) -> dict[str, Any]:
    source = _source_identity()
    if require_clean and source["dirty"]:
        raise ReleaseCandidateError("source worktree is dirty")
    _prepare_destination(outdir)

    with tempfile.TemporaryDirectory(
        prefix=f".{outdir.name}.",
        dir=outdir.parent,
    ) as temporary_directory:
        stage = Path(temporary_directory) / "candidate"
        stage.mkdir()
        _run_builder([sys.executable, str(PACKAGE_BUILDER), "--outdir", str(stage), "--sdist"])
        _run_builder([sys.executable, str(PLUGIN_BUILDER), "--outdir", str(stage)])

        artifacts, python_version, plugin_version = _inspect_distribution_artifacts(stage)
        sbom_filename = f"tooluseproxy-{python_version}.cdx.json"
        notes_filename = f"tooluseproxy-{python_version}-release-notes.md"
        license_present = (REPO_ROOT / "LICENSE").is_file()
        manifest = {
            "schema_version": 1,
            "status": "candidate",
            "product": "ToolUseProxy",
            "python_version": python_version,
            "plugin_version": plugin_version,
            "source": source,
            "gates": {
                "clean_source": not source["dirty"],
                "license_present": license_present,
                "artifact_set_eligible": not source["dirty"] and license_present,
                "ci_evidence": "external_required",
                "manual_trust_evidence": "external_required",
            },
            "artifacts": artifacts,
            "sbom": {
                "filename": sbom_filename,
                "format": "CycloneDX",
                "spec_version": SBOM_SPEC_VERSION,
            },
            "release_notes": {"filename": notes_filename},
        }
        _write_json(stage / MANIFEST_FILENAME, manifest)
        _write_json(
            stage / sbom_filename,
            _cyclonedx_sbom(
                artifacts=artifacts,
                python_version=python_version,
                plugin_version=plugin_version,
                source=source,
            ),
        )
        (stage / notes_filename).write_text(
            _release_notes(manifest),
            encoding="utf-8",
            newline="\n",
        )
        _write_checksums(stage)
        summary = verify_candidate(stage)
        stage.replace(outdir)
    return {**summary, "output_directory": str(outdir)}


def verify_candidate(directory: Path) -> dict[str, Any]:
    if not directory.is_dir() or directory.is_symlink():
        raise ReleaseCandidateError("candidate directory is missing or is a symlink")
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    if not entries or any(not path.is_file() or path.is_symlink() for path in entries):
        raise ReleaseCandidateError("candidate must contain regular files only")
    names = {path.name for path in entries}
    if MANIFEST_FILENAME not in names or CHECKSUM_FILENAME not in names:
        raise ReleaseCandidateError("candidate metadata is incomplete")

    manifest = _read_json_object(directory / MANIFEST_FILENAME)
    _validate_manifest(manifest)
    artifact_entries = manifest["artifacts"]
    assert isinstance(artifact_entries, list)
    artifact_names = {entry["filename"] for entry in artifact_entries}
    sbom = manifest["sbom"]
    release_notes = manifest["release_notes"]
    assert isinstance(sbom, dict) and isinstance(release_notes, dict)
    expected_names = {
        MANIFEST_FILENAME,
        CHECKSUM_FILENAME,
        str(sbom["filename"]),
        str(release_notes["filename"]),
        *artifact_names,
    }
    if names != expected_names:
        raise ReleaseCandidateError("candidate contains missing or unexpected files")

    checksums = _read_checksums(directory / CHECKSUM_FILENAME)
    checksum_targets = names - {CHECKSUM_FILENAME}
    if set(checksums) != checksum_targets:
        raise ReleaseCandidateError("SHA256SUMS does not cover the exact candidate file set")
    for name, expected_digest in checksums.items():
        if _sha256(directory / name) != expected_digest:
            raise ReleaseCandidateError(f"checksum mismatch: {name}")

    for artifact in artifact_entries:
        filename = str(artifact["filename"])
        path = directory / filename
        if path.stat().st_size != artifact["size"] or _sha256(path) != artifact["sha256"]:
            raise ReleaseCandidateError(f"artifact metadata mismatch: {filename}")

    python_version, plugin_version = _validate_distribution_versions(
        directory,
        artifact_entries,
    )
    if manifest["python_version"] != python_version or manifest["plugin_version"] != plugin_version:
        raise ReleaseCandidateError("manifest version does not match distribution artifacts")
    _validate_sbom(directory / str(sbom["filename"]), manifest)

    return {
        "schema_version": 1,
        "status": "verified",
        "python_version": python_version,
        "plugin_version": plugin_version,
        "source_commit": manifest["source"]["commit"],
        "artifact_count": len(artifact_entries),
        "checked_file_count": len(checksums),
        "artifact_set_eligible": manifest["gates"]["artifact_set_eligible"],
    }


def _prepare_destination(outdir: Path) -> None:
    outdir.parent.mkdir(parents=True, exist_ok=True)
    if outdir.exists():
        if outdir.is_symlink() or not outdir.is_dir():
            raise ReleaseCandidateError("output path must be a directory")
        if any(outdir.iterdir()):
            raise ReleaseCandidateError("output directory must be empty")
        outdir.rmdir()


def _source_identity() -> dict[str, Any]:
    commit = _git("rev-parse", "--verify", "HEAD")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseCandidateError("git HEAD is not a full commit id")
    timestamp = _git("show", "-s", "--format=%cI", commit)
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseCandidateError("git commit timestamp is invalid") from error
    dirty = bool(_git("status", "--porcelain", "--untracked-files=normal"))
    return {"commit": commit, "commit_timestamp": timestamp, "dirty": dirty}


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseCandidateError("git source identity is unavailable")
    return result.stdout.strip()


def _run_builder(command: list[str]) -> None:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseCandidateError("artifact builder failed")


def _inspect_distribution_artifacts(
    directory: Path,
) -> tuple[list[dict[str, Any]], str, str]:
    paths = sorted(directory.iterdir(), key=lambda path: path.name)
    roles: dict[str, tuple[str, str]] = {}
    for path in paths:
        if path.suffix == ".whl":
            roles[path.name] = ("python-wheel", "application/zip")
        elif path.name.endswith(".tar.gz"):
            roles[path.name] = ("python-sdist", "application/gzip")
        elif path.name.startswith("tooluseproxy-plugin-") and path.suffix == ".zip":
            roles[path.name] = ("codex-plugin", "application/zip")
        else:
            raise ReleaseCandidateError(f"unexpected distribution artifact: {path.name}")
    if sorted(role for role, _ in roles.values()) != [
        "codex-plugin",
        "python-sdist",
        "python-wheel",
    ]:
        raise ReleaseCandidateError("expected exactly wheel, sdist, and Plugin artifacts")
    artifacts = [
        {
            "filename": path.name,
            "role": roles[path.name][0],
            "media_type": roles[path.name][1],
            "sha256": _sha256(path),
            "size": path.stat().st_size,
        }
        for path in paths
    ]
    python_version, plugin_version = _validate_distribution_versions(directory, artifacts)
    return artifacts, python_version, plugin_version


def _validate_distribution_versions(
    directory: Path,
    artifacts: list[dict[str, Any]],
) -> tuple[str, str]:
    python_versions: set[str] = set()
    plugin_versions: set[str] = set()
    for artifact in artifacts:
        path = directory / str(artifact["filename"])
        role = artifact["role"]
        if role == "python-wheel":
            with zipfile.ZipFile(path) as archive:
                metadata_names = [
                    name
                    for name in archive.namelist()
                    if name.endswith(".dist-info/METADATA")
                ]
                if len(metadata_names) != 1:
                    raise ReleaseCandidateError("wheel METADATA is missing or ambiguous")
                metadata_name = metadata_names[0]
                metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_name))
                version = metadata["Version"]
        elif role == "python-sdist":
            with tarfile.open(path, mode="r:gz") as archive:
                metadata_members = [
                    member
                    for member in archive.getmembers()
                    if member.name.count("/") == 1
                    and member.name.endswith("/PKG-INFO")
                ]
                if len(metadata_members) != 1:
                    raise ReleaseCandidateError("sdist PKG-INFO is missing or ambiguous")
                metadata_member = metadata_members[0]
                extracted = archive.extractfile(metadata_member)
                if extracted is None:
                    raise ReleaseCandidateError("sdist PKG-INFO is unreadable")
                metadata = email.parser.BytesParser().parsebytes(extracted.read())
                version = metadata["Version"]
        elif role == "codex-plugin":
            with zipfile.ZipFile(path) as archive:
                plugin_manifest = json.loads(
                    archive.read("tooluseproxy/.codex-plugin/plugin.json").decode("utf-8")
                )
            version = plugin_manifest.get("version") if isinstance(plugin_manifest, dict) else None
            if not isinstance(version, str):
                raise ReleaseCandidateError("Plugin version is missing")
            plugin_versions.add(version)
            continue
        else:
            raise ReleaseCandidateError("unknown artifact role")
        if not isinstance(version, str) or not version:
            raise ReleaseCandidateError("Python package version is missing")
        python_versions.add(version)
    if len(python_versions) != 1 or len(plugin_versions) != 1:
        raise ReleaseCandidateError("artifact versions are inconsistent")
    python_version = python_versions.pop()
    plugin_version = plugin_versions.pop()
    if plugin_version.replace("-alpha.", "a") != python_version:
        raise ReleaseCandidateError("Python and Plugin versions are inconsistent")
    return python_version, plugin_version


def _cyclonedx_sbom(
    *,
    artifacts: list[dict[str, Any]],
    python_version: str,
    plugin_version: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    commit = str(source["commit"])
    root_ref = f"pkg:pypi/tooluseproxy@{python_version}"
    artifact_identity = "\n".join(
        f"{artifact['filename']}:{artifact['sha256']}" for artifact in artifacts
    )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"tooluseproxy:{commit}:{artifact_identity}")
    components = []
    for artifact in artifacts:
        filename = str(artifact["filename"])
        components.append(
            {
                "type": "file",
                "bom-ref": f"artifact:{filename}",
                "name": filename,
                "version": python_version,
                "hashes": [{"alg": "SHA-256", "content": artifact["sha256"]}],
                "properties": [
                    {"name": "tooluseproxy:release:role", "value": artifact["role"]}
                ],
            }
        )
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{SBOM_SPEC_VERSION}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": source["commit_timestamp"],
            "lifecycles": [{"phase": "build"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "tooluseproxy-release-candidate-builder",
                        "version": python_version,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "tooluseproxy",
                "version": python_version,
                "purl": root_ref,
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": (
                            "https://github.com/mani1261790/ToolUseProxy/tree/"
                            f"{commit}"
                        ),
                    }
                ],
                "properties": [
                    {"name": "tooluseproxy:git:commit", "value": commit},
                    {
                        "name": "tooluseproxy:plugin:version",
                        "value": plugin_version,
                    },
                ],
            },
        },
        "components": components,
        "compositions": [
            {
                "aggregate": "complete",
                "assemblies": [component["bom-ref"] for component in components],
            }
        ],
    }


def _release_notes(manifest: dict[str, Any]) -> str:
    source = manifest["source"]
    gates = manifest["gates"]
    artifacts = manifest["artifacts"]
    lines = [
        f"# ToolUseProxy {manifest['plugin_version']} release candidate",
        "",
        f"Source commit: `{source['commit']}`",
        f"Source clean: `{'yes' if gates['clean_source'] else 'no'}`",
        f"LICENSE present: `{'yes' if gates['license_present'] else 'no'}`",
        "",
        "## Artifacts",
        "",
    ]
    lines.extend(
        f"- `{artifact['filename']}` ({artifact['role']}): `{artifact['sha256']}`"
        for artifact in artifacts
    )
    lines.extend(
        [
            "",
            "## Verification",
            "",
            f"- Verify all files with `{CHECKSUM_FILENAME}`.",
            f"- Inspect `{MANIFEST_FILENAME}` for source commit and release gates.",
            f"- Inspect `{manifest['sbom']['filename']}` for the CycloneDX SBOM.",
            "- Attach the green CI run separately; CI evidence is not inferred locally.",
            "- Review and trust the exact Codex Hook definition manually.",
            "",
            "## Release gate",
            "",
            "This is a candidate artifact set, not a published release. A clean source, "
            "LICENSE, green CI, manual Hook trust dogfood, and explicit publication approval "
            "are required before release.",
            "",
        ]
    )
    return "\n".join(lines)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1 or manifest.get("status") != "candidate":
        raise ReleaseCandidateError("release manifest schema or status is invalid")
    source = manifest.get("source")
    gates = manifest.get("gates")
    artifacts = manifest.get("artifacts")
    if not isinstance(source, dict) or not isinstance(gates, dict) or not isinstance(artifacts, list):
        raise ReleaseCandidateError("release manifest structure is invalid")
    commit = source.get("commit")
    if not isinstance(commit, str) or COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseCandidateError("release manifest commit is invalid")
    if not isinstance(source.get("dirty"), bool):
        raise ReleaseCandidateError("release manifest dirty state is invalid")
    if len(artifacts) != 3:
        raise ReleaseCandidateError("release manifest must contain three artifacts")
    roles: set[str] = set()
    filenames: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ReleaseCandidateError("release manifest artifact is invalid")
        filename = artifact.get("filename")
        digest = artifact.get("sha256")
        if (
            not isinstance(filename, str)
            or PurePosixPath(filename).name != filename
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
            or not isinstance(artifact.get("size"), int)
        ):
            raise ReleaseCandidateError("release manifest artifact metadata is invalid")
        filenames.add(filename)
        roles.add(str(artifact.get("role")))
    if len(filenames) != 3 or roles != {"python-wheel", "python-sdist", "codex-plugin"}:
        raise ReleaseCandidateError("release manifest artifact set is invalid")


def _validate_sbom(path: Path, manifest: dict[str, Any]) -> None:
    sbom = _read_json_object(path)
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != SBOM_SPEC_VERSION:
        raise ReleaseCandidateError("SBOM format or specification version is invalid")
    metadata = sbom.get("metadata")
    components = sbom.get("components")
    if not isinstance(metadata, dict) or not isinstance(components, list):
        raise ReleaseCandidateError("SBOM structure is invalid")
    root = metadata.get("component")
    if not isinstance(root, dict) or root.get("version") != manifest["python_version"]:
        raise ReleaseCandidateError("SBOM root component version is invalid")
    expected = {
        artifact["filename"]: artifact["sha256"] for artifact in manifest["artifacts"]
    }
    observed: dict[str, str] = {}
    for component in components:
        if not isinstance(component, dict) or component.get("type") != "file":
            raise ReleaseCandidateError("SBOM artifact component is invalid")
        hashes = component.get("hashes")
        if not isinstance(hashes, list) or len(hashes) != 1:
            raise ReleaseCandidateError("SBOM artifact hash is invalid")
        digest = hashes[0]
        if not isinstance(digest, dict) or digest.get("alg") != "SHA-256":
            raise ReleaseCandidateError("SBOM artifact hash algorithm is invalid")
        observed[str(component.get("name"))] = str(digest.get("content"))
    if observed != expected:
        raise ReleaseCandidateError("SBOM artifact inventory does not match manifest")


def _write_checksums(directory: Path) -> None:
    lines = [
        f"{_sha256(path)}  {path.name}"
        for path in sorted(directory.iterdir(), key=lambda item: item.name)
        if path.is_file() and path.name != CHECKSUM_FILENAME
    ]
    (directory / CHECKSUM_FILENAME).write_text(
        "\n".join(lines) + "\n",
        encoding="ascii",
        newline="\n",
    )


def _read_checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseCandidateError("SHA256SUMS is unreadable") from error
    checksums: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ReleaseCandidateError("SHA256SUMS line is invalid")
        digest = line[:64]
        filename = line[66:]
        if (
            SHA256_PATTERN.fullmatch(digest) is None
            or PurePosixPath(filename).name != filename
            or filename in checksums
        ):
            raise ReleaseCandidateError("SHA256SUMS entry is invalid")
        checksums[filename] = digest
    if list(checksums) != sorted(checksums):
        raise ReleaseCandidateError("SHA256SUMS entries must be sorted")
    return checksums


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseCandidateError(f"invalid JSON metadata: {path.name}") from error
    if not isinstance(payload, dict):
        raise ReleaseCandidateError(f"JSON metadata must be an object: {path.name}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
