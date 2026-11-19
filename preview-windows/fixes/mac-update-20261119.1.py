"""Upgrade an unmodified project ZIP installation; do not open any project DB."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

BASE = Path(__file__).resolve().parent


def inventory(root):
    tree = {}
    for p in root.rglob("*"):
        if p.is_symlink():
            raise ValueError("リンクを含む本体は更新できません。")
        if p.is_dir():
            continue
        if not p.is_file():
            raise ValueError("通常ファイルでない本体は更新できません。")
        rel = p.relative_to(root)
        if "__pycache__" in rel.parts and p.suffix == ".pyc":
            continue
        tree[rel.as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return tree


def update(workspace, apply):
    if sys.platform != "darwin":
        raise ValueError("この更新はMac版専用です。")
    root = workspace.resolve(strict=True)
    control = root / ".codex/tooluseproxy-review"
    rt = control / "runtime"
    for directory in (root / ".codex", control, rt):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("Macテスター版の導入先が見つかりません。")
    target = json.loads((BASE / "runtime-manifest.json").read_text())
    previous = [json.loads((BASE / name).read_text()) for name in
                ("supported-20261108.5.json", "supported-20261108.6.json")]
    if inventory(BASE / "runtime") != target:
        raise ValueError("更新用ZIPの本体が一致しません。")
    lock = os.open(control, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        installed = inventory(rt)
        prev = next((v for v in previous if installed == v), previous[0])
        if installed not in (prev, target):
            raise ValueError("対象外の版または変更された本体です。上書きしません。")
        if not apply:
            print("20261119.1 は導入済みです。" if installed == target else
                  "20261108.5 / 20261108.6 → 20261119.1。本体と導入案内のみ更新します。")
            return
        if installed == prev:
            with tempfile.TemporaryDirectory(dir=control, prefix=".updating-") as temp:
                stage = Path(temp) / "runtime"
                shutil.copytree(BASE / "runtime", stage, ignore=shutil.ignore_patterns("__pycache__"))
                if inventory(stage) != target or inventory(rt) != prev:
                    raise ValueError("本体が変わったため更新を中止しました。")
                swap = ctypes.CDLL(None, use_errno=True).renamex_np
                if swap(os.fsencode(stage), os.fsencode(rt), 2) != 0:  # RENAME_SWAP
                    raise OSError(ctypes.get_errno(), "本体の切り替えに失敗しました。")
        with tempfile.NamedTemporaryFile(dir=control, delete=False) as f:
            f.write((BASE / "AGENT_INSTALL.md").read_bytes())
            guide = f.name
        os.replace(guide, control / "AGENT_INSTALL.md")
        print("20261119.1 に更新しました。新しいチャットで利用してください。")
    finally:
        os.close(lock)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    try:
        update(args.workspace, args.apply)
    except (ValueError, OSError) as exc:
        sys.exit(str(exc))
