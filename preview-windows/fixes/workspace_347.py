"""Apply the shared runtime fix to an unpacked, hash-verified preview kit."""
import hashlib
import json
from pathlib import Path
import sys


def patch(kit):
    kit = Path(kit)
    manifest_path = kit / "runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for name, expected in manifest.items():
        assert hashlib.sha256((kit / "runtime" / name).read_bytes()).hexdigest() == expected, name
    app = kit / "runtime/tooluseproxy/app.py"
    text = app.read_text()
    old = """            from tooluseproxy.project_storage import discover_project, require_new_project_storage
            root = discover_project(root)
"""
    new = """            # --workspace is required and explicit: never substitute an ancestor.
            from tooluseproxy.project_storage import require_new_project_storage
"""
    assert text.count(old) == 1
    text = text.replace(old, new)
    old = """    local = None
    if sum((args.openai_decisions"""
    new = """    # Validate every registration before creating config, DB, or ignore entries.
    # Reuse the same read-free validation as 'protect plan'.
    from argparse import Namespace
    for source in args.protect:
        result, code = _protect(Namespace(operation="plan", path=source), paths, root)
        if code:
            return {"status": "registration_preflight_failed",
                    "registrations": [result], "changed": False}, code

    local = None
    if sum((args.openai_decisions"""
    assert text.count(old) == 1
    text = text.replace(old, new)
    app.write_text(text, encoding="utf-8")
    manifest["tooluseproxy/app.py"] = hashlib.sha256(app.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n",encoding="utf-8")


if __name__ == "__main__":
    patch(sys.argv[1])
