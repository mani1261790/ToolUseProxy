#!/usr/bin/env python3
from __future__ import annotations

import sys


def main() -> int:
    # Placeholder hook target. Read stdin so the process behaves like a normal hook command.
    sys.stdin.buffer.read()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
