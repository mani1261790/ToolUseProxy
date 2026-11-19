"""Offline regression checks against the actual packaged runtime, on Mac or Windows."""
import json
import sqlite3
import os
from pathlib import Path
import subprocess
import sys
import tempfile

runtime = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(runtime))
from tooluseproxy.project_storage import discover_project, hook_paths
from tooluseproxy.integrations.activation import enabled_workspace_root
from tooluseproxy.integrations.authority import workspace_authority_lease

def cli(project, *args, ok=True):
    env = os.environ.copy()
    for key in ("PLUGIN_DATA", "TOOLUSEPROXY_DATA_DIR", "TOOLUSEPROXY_DB_PATH"):
        env.pop(key, None)
    result = subprocess.run(
        [sys.executable, str(runtime / "tooluseproxy_plugin.py"), *args,
         "--workspace", str(project), "--json"],
        cwd=project, env=env, capture_output=True, text=True, encoding="utf-8")
    assert (result.returncode == 0) == ok, (result.stdout, result.stderr)
    return json.loads(result.stdout)

def setup(project, *protect, ok=True):
    return cli(project, "setup", "--accept-judge-data", "--no-viewer",
               *[a for p in protect for a in ("--protect", p)], ok=ok)

with tempfile.TemporaryDirectory() as directory:
    base = Path(directory).resolve()
    for parent_kind in ("git", "configured"):
        parent = base / parent_kind
        parent.mkdir()
        (parent / ".gitignore").write_bytes(b"# parent must not change\n")
        if parent_kind == "git":
            (parent / ".git").mkdir()
        else:
            setup(parent)
        # Detect changes to every parent's file, including DB and configuration.
        before = {str(p.relative_to(parent)): p.read_bytes() for p in parent.rglob("*") if p.is_file()}
        project = parent / "proj"
        project.mkdir()
        (project / "notes.txt").write_text("synthetic test fixture", encoding="utf-8")
        out = cli(project, "setup", "--plan", "--no-viewer")
        assert not (project / ".tooluseproxy").exists()
        out = setup(project, "notes.txt")
        assert out["workspace_root"] == str(project), out
        assert out["registrations"][0]["status"] == "registered", out
        assert [s["path"] for s in cli(project, "protect", "list")["sources"]] == ["notes.txt"]
        assert setup(project, "notes.txt")["status"] == "already_configured"
        nested = project / "src"
        nested.mkdir()
        db = project / ".tooluseproxy/events.db"
        for cwd in (project, nested):
            assert discover_project(cwd) == project
            assert hook_paths(str(cwd)).db_path == db
            assert enabled_workspace_root(db, str(cwd)) == str(project)
            with workspace_authority_lease(db, str(cwd)):
                pass
        # Exercise the real runtime Hook against the installed child DB, without model calls.
        event = json.dumps(dict(cwd=str(nested), session_id="issue-347",
                                hook_event_name="SessionStart"))
        hook = subprocess.run([sys.executable, str(runtime / "tooluseproxy_plugin.py"),
                               "hook", "session-start", "--db", str(db)],
                              input=event, cwd=nested, capture_output=True,
                              text=True, encoding="utf-8")
        assert hook.returncode == 0, (hook.stdout, hook.stderr)
        with sqlite3.connect(db) as conn:
            rows = conn.execute("SELECT workspace_root FROM events WHERE session_id='issue-347'").fetchall()
        conn.close()
        assert rows and all(row[0] == str(project) for row in rows), rows
        # Independent nested repositories must retain their isolation.
        independent = project / "other"
        independent.mkdir()
        (independent / ".git").mkdir()
        assert enabled_workspace_root(db, str(independent)) is None
        assert enabled_workspace_root(db, str(parent)) is None
        after = {str(p.relative_to(parent)): p.read_bytes() for p in parent.rglob("*")
                 if p.is_file() and not p.is_relative_to(project)}
        assert after == before, "parent changed"
        bad = parent / "invalid"
        bad.mkdir()
        (bad / "valid.txt").write_text("fixture")
        out = setup(bad, "valid.txt", "missing.txt", ok=False)
        assert out["status"] == "registration_preflight_failed", out
        assert sorted(p.name for p in bad.iterdir()) == ["valid.txt"]
        print("PASS", parent_kind, "explicit setup, registration, repeat, Hook root, parent isolation, preflight")
