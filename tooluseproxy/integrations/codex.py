from __future__ import annotations

import sys
from pathlib import Path

from hook_monitor.runtime.runner import run_hook
from tooluseproxy.paths import (
    prepare_data_directory,
    resolve_runtime_paths,
    secure_database_permissions,
)


CODEX_HOOK_PHASES = {
    "pre-tool-use": "pre_tool_use",
    "post-tool-use": "post_tool_use",
    "stop": "stop",
}


def run_codex_hook(
    phase: str,
    *,
    db_path: str | Path | None = None,
    data_dir: str | Path | None = None,
) -> int:
    try:
        runtime_phase = CODEX_HOOK_PHASES[phase]
    except KeyError:
        raise ValueError(f"unsupported Codex hook phase: {phase}") from None
    try:
        paths = resolve_runtime_paths(db_path=db_path, data_dir=data_dir)
        prepare_data_directory(paths)
        try:
            return run_hook(
                runtime_phase,
                db_path=paths.db_path,
                allow_schema_migration=False,
            )
        finally:
            secure_database_permissions(paths.db_path)
    except Exception as exc:  # Hook integrations must never block Codex on local failure.
        print(
            f"ToolUseProxy inactive (runtime_error): {type(exc).__name__}",
            file=sys.stderr,
        )
        return 0
