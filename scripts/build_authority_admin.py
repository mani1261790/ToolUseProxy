"""Build a stdlib-only administrator entry point; never install or elevate it."""
from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build() -> bytes:
    state = (ROOT / "tooluseproxy" / "authority_state.py").read_text(encoding="utf-8")
    admin = (ROOT / "tooluseproxy" / "authority_admin.py").read_text(encoding="utf-8")
    return compose(state, admin)


def compose(state: str, admin: str) -> bytes:
    tree = ast.parse(admin)
    lines = admin.splitlines(keepends=True)
    excluded = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in (
            "__future__", "tooluseproxy.authority_state",
        ):
            excluded.update(range(node.lineno - 1, node.end_lineno))
    combined = state + "\n\n" + "".join(line for index, line in enumerate(lines)
                                          if index not in excluded)
    compile(combined, "authority-admin.py", "exec")
    return combined.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = build()
    # Exclusive creation avoids replacing user files or following a symlink.
    with args.output.open("xb") as stream:
        stream.write(payload)
    print("sha256: " + hashlib.sha256(payload).hexdigest())
    print("未導入です。管理者による検証・導入が必要です。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
