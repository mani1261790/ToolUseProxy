#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIRECTORY = "tooluseproxy"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_FILES = (
    ".codex-plugin/plugin.json",
    "hooks/hooks.json",
    "hooks/run_cli.cmd",
    "hooks/run_cli.sh",
    "hooks/run_hook.cmd",
    "hooks/run_hook.sh",
    "skills/tooluseproxy-setup/SKILL.md",
    "tooluseproxy_plugin.py",
)
PYTHON_PACKAGE_DIRECTORIES = ("hook_monitor", "tooluseproxy")
EXCLUDED_PYTHON_DIRECTORIES = (PurePosixPath("hook_monitor/evaluation"),)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the minimal, relocatable ToolUseProxy Codex Plugin bundle.",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="Artifact directory. Defaults to repository dist/.",
    )
    args = parser.parse_args()

    outdir = args.outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = _read_json(REPO_ROOT / ".codex-plugin" / "plugin.json")
    version = _validated_version(manifest)
    artifact = outdir / f"tooluseproxy-plugin-{version}.zip"
    files = _plugin_files()
    marketplace = _render_marketplace()

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{artifact.name}.",
        suffix=".tmp",
        dir=outdir,
    )
    os.close(file_descriptor)
    temporary_artifact = Path(temporary_name)
    try:
        with zipfile.ZipFile(
            temporary_artifact,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            _write_bytes(
                archive,
                ".agents/plugins/marketplace.json",
                marketplace,
                executable=False,
            )
            for source, relative_path in files:
                _write_bytes(
                    archive,
                    str(PurePosixPath(PLUGIN_DIRECTORY) / relative_path),
                    source.read_bytes(),
                    executable=relative_path.suffix == ".sh",
                )
        temporary_artifact.replace(artifact)
    finally:
        temporary_artifact.unlink(missing_ok=True)

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    print(f"{artifact}\tsha256={digest}")
    return 0


def _plugin_files() -> list[tuple[Path, PurePosixPath]]:
    relative_paths = [PurePosixPath(path) for path in FIXED_FILES]
    for directory in PYTHON_PACKAGE_DIRECTORIES:
        relative_paths.extend(
            PurePosixPath(path.relative_to(REPO_ROOT).as_posix())
            for path in (REPO_ROOT / directory).rglob("*.py")
            if not _is_excluded_python_file(path)
        )

    files: list[tuple[Path, PurePosixPath]] = []
    for relative_path in sorted(set(relative_paths), key=str):
        source = REPO_ROOT / Path(relative_path)
        _validate_source_file(source, relative_path)
        files.append((source, relative_path))
    return files


def _is_excluded_python_file(path: Path) -> bool:
    relative_path = PurePosixPath(path.relative_to(REPO_ROOT).as_posix())
    return any(relative_path.is_relative_to(excluded) for excluded in EXCLUDED_PYTHON_DIRECTORIES)


def _validate_source_file(source: Path, relative_path: PurePosixPath) -> None:
    if not source.is_file():
        raise SystemExit(f"required Plugin file is missing: {relative_path}")
    current = source
    while current != REPO_ROOT:
        if current.is_symlink():
            raise SystemExit(f"Plugin bundle refuses symlinks: {relative_path}")
        current = current.parent
    if REPO_ROOT not in source.resolve().parents:
        raise SystemExit(f"Plugin file escapes repository root: {relative_path}")


def _render_marketplace() -> bytes:
    marketplace = _read_json(REPO_ROOT / ".agents" / "plugins" / "marketplace.json")
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list) or len(plugins) != 1:
        raise SystemExit("marketplace must declare exactly one Plugin")
    plugin = plugins[0]
    if not isinstance(plugin, dict) or plugin.get("name") != PLUGIN_DIRECTORY:
        raise SystemExit("marketplace Plugin name must be tooluseproxy")
    plugin["source"] = {"source": "local", "path": f"./{PLUGIN_DIRECTORY}"}
    return (json.dumps(marketplace, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _validated_version(manifest: object) -> str:
    if not isinstance(manifest, dict):
        raise SystemExit("Plugin manifest must be a JSON object")
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit("Plugin manifest version must be a non-empty string")
    python_version = _python_package_version()
    if version.replace("-alpha.", "a") != python_version:
        raise SystemExit(
            f"Plugin version {version!r} does not match Python package {python_version!r}"
        )
    return version


def _python_package_version() -> str:
    version_file = REPO_ROOT / "tooluseproxy" / "__init__.py"
    try:
        module = ast.parse(version_file.read_text(encoding="utf-8"), filename=str(version_file))
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        raise SystemExit(f"cannot read Python package version: {error}") from error
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        is_version_assignment = any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        )
        if is_version_assignment:
            try:
                version = ast.literal_eval(statement.value)
            except (ValueError, TypeError) as error:
                raise SystemExit(
                    "tooluseproxy.__version__ must be a non-empty string literal"
                ) from error
            if isinstance(version, str) and version:
                return version
    raise SystemExit("tooluseproxy.__version__ must be a non-empty string literal")


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read {path.relative_to(REPO_ROOT)}: {error}") from error


def _write_bytes(
    archive: zipfile.ZipFile,
    name: str,
    content: bytes,
    *,
    executable: bool,
) -> None:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = (0o100000 | mode) << 16
    archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


if __name__ == "__main__":
    raise SystemExit(main())
