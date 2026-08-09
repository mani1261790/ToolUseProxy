from __future__ import annotations

import os
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


DB_PATH_ENV = "TOOLUSEPROXY_DB_PATH"
DATA_DIR_ENV = "TOOLUSEPROXY_DATA_DIR"
PLUGIN_DATA_ENV = "PLUGIN_DATA"
CODEX_HOME_ENV = "CODEX_HOME"
CODEX_PLUGIN_ROOT_ENV = "TOOLUSEPROXY_CODEX_PLUGIN_ROOT"
DEFAULT_DB_FILENAME = "events.db"


class PathConfigurationError(ValueError):
    """Raised when runtime path settings are ambiguous or invalid."""


@dataclass(frozen=True)
class RuntimePaths:
    data_dir: Path
    db_path: Path
    source: str


def resolve_runtime_paths(
    *,
    db_path: str | Path | None = None,
    data_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> RuntimePaths:
    """Resolve one stable writable location without depending on source layout."""
    if db_path is not None and data_dir is not None:
        raise PathConfigurationError("--db and --data-dir cannot be used together")

    env = os.environ if environ is None else environ
    if db_path is not None:
        resolved_db = _absolute_path(db_path)
        return RuntimePaths(resolved_db.parent, resolved_db, "explicit_db")
    if data_dir is not None:
        resolved_dir = _absolute_path(data_dir)
        return RuntimePaths(
            resolved_dir,
            resolved_dir / DEFAULT_DB_FILENAME,
            "explicit_data_dir",
        )

    codex_plugin_root = _nonempty(env.get(CODEX_PLUGIN_ROOT_ENV))
    if codex_plugin_root is not None:
        return resolve_codex_plugin_runtime_paths(
            plugin_root=codex_plugin_root,
            environ=env,
            home=home,
        )

    configured_db = _nonempty(env.get(DB_PATH_ENV))
    if configured_db is not None:
        resolved_db = _absolute_path(configured_db)
        return RuntimePaths(resolved_db.parent, resolved_db, "environment_db")

    configured_dir = _nonempty(env.get(DATA_DIR_ENV))
    if configured_dir is not None:
        resolved_dir = _absolute_path(configured_dir)
        return RuntimePaths(
            resolved_dir,
            resolved_dir / DEFAULT_DB_FILENAME,
            "environment_data_dir",
        )

    plugin_data = _nonempty(env.get(PLUGIN_DATA_ENV))
    if plugin_data is not None:
        resolved_dir = _absolute_path(plugin_data)
        return RuntimePaths(
            resolved_dir,
            resolved_dir / DEFAULT_DB_FILENAME,
            "plugin_data",
        )

    resolved_dir = default_user_data_dir(
        environ=env,
        platform=platform,
        home=home,
    )
    return RuntimePaths(
        resolved_dir,
        resolved_dir / DEFAULT_DB_FILENAME,
        "platform_default",
    )


def resolve_codex_plugin_runtime_paths(
    *,
    plugin_root: str | Path,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> RuntimePaths:
    """Resolve Codex's legacy Plugin data root from a verified install root."""
    env = os.environ if environ is None else environ
    user_home = Path.home() if home is None else home
    configured_home = _nonempty(env.get(CODEX_HOME_ENV))
    codex_home = _absolute_path(
        configured_home if configured_home is not None else user_home / ".codex"
    )
    try:
        canonical_home = codex_home.resolve(strict=True)
        canonical_root = _absolute_path(plugin_root).resolve(strict=True)
        cache_root = (canonical_home / "plugins" / "cache").resolve(strict=True)
        relative = canonical_root.relative_to(cache_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PathConfigurationError(
            "installed Codex Plugin root could not be verified"
        ) from exc

    if len(relative.parts) != 3:
        raise PathConfigurationError(
            "installed Codex Plugin root has an unsupported layout"
        )
    marketplace_name, plugin_name, plugin_version = relative.parts
    if not all(
        _safe_codex_plugin_segment(value)
        for value in (marketplace_name, plugin_name, plugin_version)
    ):
        raise PathConfigurationError(
            "installed Codex Plugin identity is invalid"
        )

    manifest_path = canonical_root / ".codex-plugin" / "plugin.json"
    try:
        if manifest_path.stat().st_size > 64 * 1024:
            raise ValueError
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PathConfigurationError(
            "installed Codex Plugin manifest could not be verified"
        ) from exc
    if not isinstance(manifest, dict) or manifest.get("name") != plugin_name:
        raise PathConfigurationError(
            "installed Codex Plugin identity does not match its manifest"
        )

    data_dir = canonical_home / "plugins" / "data" / (
        f"{plugin_name}-{marketplace_name}"
    )
    return RuntimePaths(
        data_dir=data_dir,
        db_path=data_dir / DEFAULT_DB_FILENAME,
        source="codex_plugin_store",
    )


def default_user_data_dir(
    *,
    environ: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    env = os.environ if environ is None else environ
    current_platform = sys.platform if platform is None else platform
    user_home = Path.home() if home is None else home
    if current_platform == "darwin":
        return user_home / "Library" / "Application Support" / "ToolUseProxy"
    if current_platform.startswith("win"):
        local_app_data = _nonempty(env.get("LOCALAPPDATA"))
        base = _absolute_path(local_app_data) if local_app_data else user_home / "AppData" / "Local"
        return base / "ToolUseProxy"
    xdg_state_home = _nonempty(env.get("XDG_STATE_HOME"))
    base = _absolute_path(xdg_state_home) if xdg_state_home else user_home / ".local" / "state"
    return base / "tooluseproxy"


def prepare_data_directory(paths: RuntimePaths) -> None:
    existed = paths.data_dir.exists()
    paths.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix" and not existed:
        paths.data_dir.chmod(0o700)


def secure_database_permissions(db_path: Path) -> None:
    if os.name == "posix" and db_path.exists():
        db_path.chmod(0o600)


def _absolute_path(value: str | Path) -> Path:
    expanded = Path(value).expanduser()
    return Path(os.path.abspath(os.fspath(expanded)))


def _nonempty(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value


def _safe_codex_plugin_segment(value: str) -> bool:
    return bool(value) and value not in {".", ".."} and all(
        character.isascii()
        and (character.isalnum() or character in {"-", "_", ".", "+"})
        for character in value
    )
