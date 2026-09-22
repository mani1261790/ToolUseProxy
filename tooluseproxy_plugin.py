#!/usr/bin/env python3
"""Codex Plugin entrypoint kept at plugin root for import-safe source execution."""

from tooluseproxy.app import main


if __name__ == "__main__":
    raise SystemExit(main())
