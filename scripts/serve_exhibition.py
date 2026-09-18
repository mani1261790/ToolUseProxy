"""Read-only, loopback viewer for the existing ToolUseProxy event database."""
from __future__ import annotations

import argparse
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
from time import monotonic
from urllib.parse import parse_qs, urlsplit

ASSETS = Path(__file__).resolve().parents[1] / "docs" / "exhibition"
COLUMNS = "event_id, phase, session_id, tool_use_id, tool_name, workspace_id, recorded_at, sequence_no"
PAYLOAD_LIMIT = 131072


class LogReader:
    def __init__(self, path: Path):
        self.path = path.resolve()
        if self.path.name != "events.db":
            raise ValueError("Select the existing events.db")

    def connect(self):
        conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=0.25)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        deadline = monotonic() + 2
        conn.set_progress_handler(lambda: int(monotonic() > deadline), 10000)
        return conn

    def snapshot(self):
        with closing(self.connect()) as conn:
            conn.execute("BEGIN")
            rows = conn.execute(
                f"SELECT {COLUMNS} FROM events ORDER BY rowid DESC LIMIT 300"
            ).fetchall()
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
            blocked = set()
            if rows and {"policy_decisions", "sink_candidates"} <= tables:
                placeholders = ",".join("?" for _ in rows)
                blocked = {row[0] for row in conn.execute(
                    "SELECT json_extract(s.metadata_json,'$.event_id') "
                    "FROM sink_candidates s JOIN policy_decisions p ON p.sink_node_id=s.node_id "
                    f"WHERE s.sequence_no IN ({placeholders}) AND p.action='block' "
                    "AND json_valid(s.metadata_json)",
                    [row["sequence_no"] for row in rows],
                )}
        calls = {}
        for row in rows:
            event = dict(row)
            if not event["tool_name"]:
                continue
            key = (event["workspace_id"], event["session_id"],
                   (event["tool_use_id"] if event["session_id"] else None) or event["event_id"])
            if key not in calls:
                calls[key] = event | {"phases": [], "blocked": False}
            calls[key]["phases"].append(event["phase"])
            calls[key]["blocked"] |= event["event_id"] in blocked
        return {"database": str(self.path), "calls": list(calls.values()), "window": 300}

    def detail(self, event_id):
        with closing(self.connect()) as conn:
            conn.execute("BEGIN")
            selected = conn.execute(
                f"SELECT {COLUMNS} FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            if selected is None:
                return {"events": [], "decisions": []}
            if selected["tool_use_id"] and selected["session_id"]:
                where = "workspace_id IS ? AND session_id=? AND tool_use_id=?"
                params = (selected["workspace_id"], selected["session_id"], selected["tool_use_id"])
            else:
                where, params = "event_id=?", (event_id,)
            rows = conn.execute(
                f"SELECT {COLUMNS}, substr(payload_json,1,?) AS payload, "
                f"length(payload_json)>? AS truncated FROM events WHERE {where} "
                "ORDER BY sequence_no DESC LIMIT 50",
                (PAYLOAD_LIMIT, PAYLOAD_LIMIT, *params),
            ).fetchall()
            events, decisions = [], []
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
            for row in reversed(rows):
                event = dict(row)
                raw = event.pop("payload")
                try:
                    payload = json.loads(raw) if not event["truncated"] else None
                except (ValueError, RecursionError):
                    payload = None
                event["payload"] = payload if isinstance(payload, dict) else {"saved_text": raw}
                events.append(event)
                if {"policy_decisions", "sink_candidates"} <= tables:
                    decisions.extend(dict(item) for item in conn.execute(
                        "SELECT DISTINCT p.decision_id,p.action,p.hook_event,p.reason,"
                        "p.user_message,p.created_at FROM policy_decisions p "
                        "JOIN sink_candidates s ON s.node_id=p.sink_node_id "
                        "WHERE s.sequence_no=? AND json_valid(s.metadata_json) "
                        "AND json_extract(s.metadata_json,'$.event_id')=? LIMIT 100",
                        (event["sequence_no"], event["event_id"]),
                    ))
            return {"events": events, "decisions": decisions, "event_limit": 50}


def make_server(reader, port=0):
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Never write event contents or the access URL into request logs.

        def do_GET(self):
            host = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != host or self.headers.get("Origin", f"http://{host}") != f"http://{host}":
                self.send_error(403)
                return
            path = urlsplit(self.path)
            prefix = f"/{token}/"
            if not path.path.startswith(prefix):
                self.send_error(404)
                return
            route = path.path[len(prefix):]
            status = 200
            if route in {"api/events", "api/detail"}:
                try:
                    result = (reader.snapshot() if route == "api/events" else reader.detail(
                        parse_qs(path.query).get("id", [""])[0]))
                except (sqlite3.Error, OSError):
                    status, result = 503, {"error": "DBに接続できません。保存先・権限・DBの状態を確認してください。"}
                body = json.dumps(result, ensure_ascii=False).encode()
                mime = "application/json; charset=utf-8"
            elif route in {"", "index.html", "screen.js", "screen.css"}:
                name = route or "index.html"
                body = (ASSETS / name).read_bytes()
                mime = {"index.html": "text/html; charset=utf-8", "screen.js": "text/javascript", "screen.css": "text/css"}[name]
            else:
                self.send_error(404)
                return
            self.send_response(status)
            for key, value in {
                "Content-Type": mime, "Content-Length": str(len(body)),
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            }.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return server, f"http://127.0.0.1:{server.server_port}/{token}/"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="Existing ToolUseProxy events.db")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server, url = make_server(LogReader(args.db), args.port)
    print(f"ToolUseProxy ログビューアー: {url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
