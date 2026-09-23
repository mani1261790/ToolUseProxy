"""Start/reuse the local viewer and return its URL to the host UI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import http.client
from pathlib import Path
from urllib.parse import urlsplit

from tooluseproxy.engine.graph import digest


def issued_viewer_open(
    db: Path, workspace: str, workspace_id: str, tool_name: object, tool_input: object
) -> bool:
    """Recognize only the exact local viewer capability issued for this workspace."""
    if tool_name != "mcp__codex_app__open_in_codex" or not isinstance(tool_input, dict):
        return False
    if set(tool_input) - {"target", "placement"}:
        return False
    if tool_input.get("placement") not in (None, "right", "bottom"):
        return False
    target = tool_input.get("target")
    if not isinstance(target, dict) or set(target) != {"type", "url"}:
        return False
    if target.get("type") != "browser" or not isinstance(target.get("url"), str):
        return False

    status = db.parent / ("viewer-" + digest(workspace) + ".json")
    try:
        metadata = status.lstat()
        if status.is_symlink() or not status.is_file():
            return False
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            return False
        if metadata.st_size > 8192:
            return False
        record = json.loads(status.read_text(encoding="utf-8"))
        issued = record.get("url")
        parsed = urlsplit(issued)
        valid = bool(
            record.get("status") == "ready"
            and record.get("workspace_root") == workspace
            and record.get("workspace_id") == workspace_id
            and issued == target["url"]
            and parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and parsed.query == ""
            and parsed.fragment == ""
            and parsed.path.startswith("/")
            and len(parsed.path) > 2
        )
        if not valid:
            return False
        connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=0.5)
        try:
            connection.request("GET", parsed.path, headers={"Host": f"127.0.0.1:{parsed.port}"})
            response = connection.getresponse()
            response.read(1024)
            return response.status == 200 and response.getheader("X-ToolUseProxy-Viewer") == "v1"
        finally:
            connection.close()
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def start(db: Path, workspace: Path):
    status = db.parent / ("viewer-" + digest(str(workspace)) + ".json")
    if status.exists() and not status.is_symlink():
        try:
            record = json.loads(status.read_text())
            url = record["url"]
            if urlsplit(url).hostname != "127.0.0.1":
                raise ValueError("invalid_viewer_host")
            parts = urlsplit(url)
            connection = http.client.HTTPConnection("127.0.0.1", parts.port, timeout=0.5)
            try:
                connection.request("GET", parts.path or "/")
                if connection.getresponse().status == 200:
                    return record
            finally:
                connection.close()
        except Exception:
            pass
    fd = os.open(
        status, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as output:
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tooluseproxy.app",
                "logs",
                "--foreground",
                "--db",
                str(db),
                "--workspace",
                str(workspace),
                "--json",
            ],
            stdout=output,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            cwd=Path(__file__).resolve().parents[1],
        )
    # macOS host-name resolution during HTTPServer startup can exceed five seconds.
    until = time.monotonic() + 30
    while time.monotonic() < until:
        try:
            return json.loads(status.read_text())
        except (ValueError, OSError):
            if child.poll() is not None:
                break
            time.sleep(0.05)
    return {
        "status": "viewer_unavailable",
        "reason": "startup_timeout" if child.poll() is None else "process_exited",
        "message": "ログUIを起動できませんでした。設定は保持されています。",
    }
