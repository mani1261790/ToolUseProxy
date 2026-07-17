#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
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
        source = Path(temporary_directory) / "source"
        shutil.copytree(REPO_ROOT, source, ignore=_ignore_source_entry)
        command = [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(outdir),
        ]
        if not args.sdist:
            command.append("--wheel")
        subprocess.run(command, cwd=source, check=True)
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


if __name__ == "__main__":
    raise SystemExit(main())
