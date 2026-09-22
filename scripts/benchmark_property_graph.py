"""Synthetic SQLite storage benchmark; no LLM, Hook, or real project data."""

import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from time import perf_counter

from tooluseproxy.engine.property_graph import schema, reach, bindings


def measure(size):
    with TemporaryDirectory(prefix="tup-graph-benchmark-") as directory:
        db = Path(directory) / "events.db"
        with sqlite3.connect(db) as conn:
            schema(conn)
            start = perf_counter()
            conn.executemany(
                "INSERT INTO graph_heads VALUES (?,?,?,?)",
                [("w", "s", str(i), str(i)) for i in range(size)],
            )
            conn.executemany(
                "INSERT INTO graph_edges VALUES (?,?,?,?)",
                [(str(i), str(i - 1), str(i), "synthetic") for i in range(1, size)],
            )
            conn.execute(
                "INSERT INTO graph_accesses VALUES ('0','0','private.txt','read','synthetic')"
            )
            conn.commit()
            build = perf_counter() - start
            start = perf_counter()
            roots, complete = bindings(
                conn, "w", "s", [{"node_id": "source:p", "path": "private.txt"}]
            )
            binding = perf_counter() - start
            assert complete
            start = perf_counter()
            path = reach(conn, "w", "s", str(size - 1), roots)
            walk = perf_counter() - start
            assert len(path) == size + 1
            start = perf_counter()
            conn.execute(
                "INSERT INTO graph_heads VALUES (?,?,?,?)", ("w", "s", str(size), str(size))
            )
            conn.execute(
                "INSERT INTO graph_edges VALUES (?,?,?,?)",
                (str(size), str(size - 1), str(size), "synthetic"),
            )
            conn.commit()
            delta = perf_counter() - start
        return {
            "nodes": size,
            "initial_insert_s": round(build, 4),
            "bind_ms": round(binding * 1000, 3),
            "full_chain_walk_s": round(walk, 4),
            "delta_commit_ms": round(delta * 1000, 3),
            "bytes": db.stat().st_size,
        }


if __name__ == "__main__":
    print(
        json.dumps(
            {
                "scope": "SQLite derived graph only; excludes inference and event replay",
                "measurements": [measure(10_000), measure(100_000)],
            },
            indent=2,
        )
    )
