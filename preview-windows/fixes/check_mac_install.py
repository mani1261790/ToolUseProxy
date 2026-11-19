"""Real Mac installer and generated SessionStart command; synthetic data only."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import tomllib

kit = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as tmp:
    parent = Path(tmp).resolve()
    (parent / ".git").mkdir()
    sentinel = parent / ".gitignore"
    sentinel.write_bytes(b"# parent sentinel\n")
    project = parent / "Project テスト"
    project.mkdir()
    (project / "notes.txt").write_text("Synthetic reference")
    command = [sys.executable, str(kit / "install.py"), "--workspace", str(project),
               "--accept-judge-data", "--protect", "notes.txt"]
    def run(command, **kwargs):
        p = subprocess.run(command, cwd=project, text=True, capture_output=True, **kwargs)
        assert p.returncode == 0, (p.stdout, p.stderr)
        return p
    run(command + ["--plan"])
    assert not (project / ".codex").exists()
    run(command)
    assert sentinel.read_bytes() == b"# parent sentinel\n"
    assert not (parent / ".tooluseproxy").exists()
    config = tomllib.loads((project / ".codex/config.toml").read_text())
    hook = config["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    run(hook, shell=True, input=json.dumps(dict(cwd=str(project),
            session_id="347-installed", hook_event_name="SessionStart")))
    with sqlite3.connect(project / ".tooluseproxy/events.db") as conn:
        assert conn.execute("SELECT workspace_root FROM events WHERE session_id='347-installed'").fetchone()[0] == str(project)
    conn.close()
    bad = parent / "bad"
    bad.mkdir()
    p = subprocess.run([sys.executable, str(kit / "install.py"), "--workspace", str(bad),
        "--protect", "missing.txt", "--accept-judge-data"], capture_output=True, text=True)
    assert p.returncode != 0 and list(bad.iterdir()) == []
    print("PASS actual Mac installer, generated Hook, parent unchanged, missing source no writes")
