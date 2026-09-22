"""Detached provenance worker; events.db remains the durable queue."""

import argparse
import fcntl
import subprocess
import sys
from pathlib import Path

from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.jobs import drain


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
        drain(args.db, args.scope)


if __name__ == "__main__":
    main()
