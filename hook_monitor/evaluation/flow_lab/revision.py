"""Pin the search implementation independently of the detector image revision."""
from __future__ import annotations

import hashlib
from pathlib import Path


FILES = (
    "agent.py", "adaptive_transport.py", "budget.py", "codex_agent.py", "controller.py",
    "models.py", "preflight.py", "revision.py", "runner.py", "search_runner.py",
    "search_state.py", "storage.py", "transport.py",
)


def implementation_revision() -> str:
    digest = hashlib.sha256()
    root = Path(__file__).parent
    for name in FILES:
        digest.update(name.encode() + b"\0")
        digest.update((root / name).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
