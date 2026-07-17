#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import sys


def main() -> int:
    entrypoint = Path(__file__).resolve().parents[1] / "tooluseproxy_plugin.py"
    os.execv(
        sys.executable,
        (sys.executable, str(entrypoint), "hook", "stop"),
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
