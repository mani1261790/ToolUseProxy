#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.runtime.sink_payload_shadow import (  # noqa: E402
    build_sink_payload_shadow_report,
    list_sink_payload_shadow_observations,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report aggregate, value-free file payload shadow observations."
        )
    )
    parser.add_argument("--db", type=Path, required=True)
    arguments = parser.parse_args()
    observations = list_sink_payload_shadow_observations(arguments.db)
    print(
        json.dumps(
            build_sink_payload_shadow_report(observations),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
