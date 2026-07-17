#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.cli.trace import main  # noqa: E402
from hook_monitor.runtime.storage import DEFAULT_DB_PATH  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        main(
            default_db_path=REPO_ROOT / DEFAULT_DB_PATH,
            allow_schema_migration=True,
        )
    )
