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
    until = time.monotonic() + 5
    while time.monotonic() < until:
        try:
            return json.loads(status.read_text())
        except (ValueError, OSError):
            if child.poll() is not None:
                break
            time.sleep(0.05)
    return {
        "status": "viewer_unavailable",
        "message": "ログUIを起動できませんでした。設定は保持されています。",
    }
