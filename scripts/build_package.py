#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
IGNORED_NAMES = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".tooluseproxy",
    ".venv",
    "build",
    "dist",
    "output",
    "__pycache__",
}
FIXED_ARCHIVE_TIMESTAMP = 315532800
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build ToolUseProxy from a clean temporary source stage.",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="Artifact directory. Defaults to repository dist/.",
    )
    parser.add_argument(
        "--sdist",
        action="store_true",
        help="Build an sdist as well as the wheel.",
    )
    args = parser.parse_args()
    outdir = args.outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="tooluseproxy-build-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        source = temporary_root / "source"
        artifact_stage = temporary_root / "artifacts"
        artifact_stage.mkdir()
        shutil.copytree(REPO_ROOT, source, ignore=_ignore_source_entry)
        command = [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(artifact_stage),
        ]
        if not args.sdist:
            command.append("--wheel")
        subprocess.run(command, cwd=source, check=True)
        artifacts = sorted(path for path in artifact_stage.iterdir() if path.is_file())
        expected_count = 2 if args.sdist else 1
        if len(artifacts) != expected_count:
            raise SystemExit(
                f"expected {expected_count} package artifact(s), found {len(artifacts)}"
            )
        for artifact in artifacts:
            if artifact.suffix == ".whl":
                _canonicalize_wheel(artifact)
            elif artifact.name.endswith(".tar.gz"):
                _canonicalize_sdist(artifact)
            else:
                raise SystemExit(f"unexpected package artifact: {artifact.name}")
            destination = outdir / artifact.name
            _atomic_copy(artifact, destination)
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            print(f"{destination}\tsha256={digest}")
    return 0


def _ignore_source_entry(directory: str, names: list[str]) -> set[str]:
    del directory
    return {
        name
        for name in names
        if name in IGNORED_NAMES
        or name == ".DS_Store"
        or name.endswith(".egg-info")
        or name.endswith((".pyc", ".pyo"))
    }


def _canonicalize_wheel(path: Path) -> None:
    canonical = path.with_name(f".{path.name}.canonical")
    try:
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(
            canonical,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as destination:
            for name in sorted(source.namelist()):
                source_info = source.getinfo(name)
                if source_info.is_dir():
                    continue
                info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100000 | 0o644) << 16
                destination.writestr(
                    info,
                    source.read(name),
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
        canonical.replace(path)
    finally:
        canonical.unlink(missing_ok=True)


def _canonicalize_sdist(path: Path) -> None:
    canonical = path.with_name(f".{path.name}.canonical")
    try:
        with tarfile.open(path, mode="r:gz") as source, canonical.open("wb") as raw_output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=FIXED_ARCHIVE_TIMESTAMP,
            ) as compressed_output:
                with tarfile.open(
                    fileobj=compressed_output,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as destination:
                    for source_info in sorted(source.getmembers(), key=lambda item: item.name):
                        info = tarfile.TarInfo(source_info.name)
                        info.mtime = FIXED_ARCHIVE_TIMESTAMP
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        if source_info.isdir():
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            destination.addfile(info)
                            continue
                        if not source_info.isfile():
                            raise SystemExit(
                                f"sdist contains unsupported entry: {source_info.name}"
                            )
                        extracted = source.extractfile(source_info)
                        if extracted is None:
                            raise SystemExit(f"cannot read sdist entry: {source_info.name}")
                        content = extracted.read()
                        info.type = tarfile.REGTYPE
                        info.mode = 0o644
                        info.size = len(content)
                        destination.addfile(info, fileobj=io.BytesIO(content))
        canonical.replace(path)
    finally:
        canonical.unlink(missing_ok=True)


def _atomic_copy(source: Path, destination: Path) -> None:
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(file_descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
