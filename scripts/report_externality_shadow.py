#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.runtime.externality_shadow import (  # noqa: E402
    build_externality_shadow_report,
    list_externality_shadow_observations,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render aggregate, value-free Externality Judge shadow metrics."
    )
    parser.add_argument("--db", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build_externality_shadow_report(
            list_externality_shadow_observations(args.db)
        )
    except (sqlite3.Error, RuntimeError, OSError) as error:
        print(f"Externality shadow report error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
