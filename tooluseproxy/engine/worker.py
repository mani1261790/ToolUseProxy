"""Detached provenance worker; events.db remains the durable queue."""

import argparse
import fcntl
import subprocess
import sys
import time
import sqlite3
from pathlib import Path

from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.jobs import drain
from tooluseproxy.engine.pending import resume


def kick(db, scope):
    subprocess.Popen(
        [sys.executable, "-m", "tooluseproxy.engine.worker", "--db", str(db), "--scope", scope],
        cwd=Path(__file__).resolve().parents[2],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--scope", required=True)
    args = parser.parse_args()
    locks = args.db.parent / "semantic-flow-locks"
    locks.mkdir(mode=0o700, exist_ok=True)
    with (locks / ("worker-" + digest(args.scope))).open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        # A finite batch avoids runaway provider use. Pending jobs survive exit.
        resume(args.db, args.scope)
        drain(args.db, args.scope)
        # Follow a short outage automatically with backoff. Persistent outages
        # stay in the durable queue for the next Hook or explicit analyze run.
        for _ in range(3):
            with sqlite3.connect(args.db) as conn:
                exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name='pending_judgments'").fetchone()
                row = conn.execute("SELECT MIN(retry_at) FROM pending_judgments WHERE workspace=? AND state='waiting'",
                                   (args.scope,)).fetchone() if exists else None
            if not row or row[0] is None or row[0] - time.time() > 60:
                break
            time.sleep(max(0, row[0] - time.time()))
            resume(args.db, args.scope)


if __name__ == "__main__":
    main()
