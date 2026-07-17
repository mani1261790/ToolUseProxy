from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


DB_PATH_ENV = "TOOLUSEPROXY_DB_PATH"
DATA_DIR_ENV = "TOOLUSEPROXY_DATA_DIR"
PLUGIN_DATA_ENV = "PLUGIN_DATA"
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
