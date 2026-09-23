"""Read-only, loopback viewer for the existing ToolUseProxy event database."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
from socketserver import TCPServer
from time import monotonic
from urllib.parse import parse_qs, urlsplit

ASSETS = Path(__file__).resolve().parent / "viewer"
COLUMNS = "event_id, phase, session_id, tool_use_id, tool_name, workspace_id, recorded_at, sequence_no"
PAYLOAD_LIMIT = 131072


class LogReader:
    def __init__(self, path: Path, workspace_id: str | None = None,
                 workspace_root: Path | None = None):
        self.path = path.resolve()
        self.workspace_id = workspace_id
        self.workspace_root = workspace_root
        if self.path.name != "events.db":
            raise ValueError("Select the existing events.db")

    @contextmanager
    def access(self):
        if self.workspace_root is None:
            yield
            return
        from tooluseproxy.integrations.authority import workspace_authority_lease

        with workspace_authority_lease(self.path, str(self.workspace_root)) as state:
            if state is not None and state.phase != "active":
                raise OSError("workspace administratively stopped")
            yield

    def connect(self):
        conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=0.25)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        deadline = monotonic() + 2
        conn.set_progress_handler(lambda: int(monotonic() > deadline), 10000)
        return conn

    def attach_forecasts(self, conn):
        """Optional local audit only; missing/broken forecast storage is not activation."""
        path = self.path.parent / "forecast.db"
        if not path.is_file() or path.is_symlink():
            return False
        try:
            conn.execute("ATTACH DATABASE ? AS forecast", (path.as_uri() + "?mode=ro",))
            if conn.execute("PRAGMA forecast.user_version").fetchone()[0] != 1:
                return False
            conn.execute("SELECT id,workspace,body,application FROM forecast.requests LIMIT 0")
            return True
        except sqlite3.Error:
            return False

    def scopes(self):
        with closing(self.connect()) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
            query = (
                "SELECT workspace_id, session_id, MAX(sequence_no) AS latest "
                "FROM events "
                + ("WHERE workspace_id=? " if self.workspace_id is not None else "")
                + "GROUP BY workspace_id, session_id ORDER BY latest DESC LIMIT 1001"
            )
            initialized = "0"
            root = "NULL"
            join = ""
            if "workspaces" in tables:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(workspaces)")}
                if "workspace_id" in columns:
                    if "canonical_root" in columns:
                        root = "w.canonical_root"
                    if "discovered_by" in columns:
                        initialized = "COALESCE(w.discovered_by IN ('init','setup_profile'), 0)"
                    join = "LEFT JOIN workspaces w ON w.workspace_id=g.workspace_id "
            saved = ("EXISTS (SELECT 1 FROM workspace_runtime_settings rs "
                     "WHERE rs.workspace_id=g.workspace_id)"
                     if "workspace_runtime_settings" in tables else "NULL")
            boundary = ("(SELECT started_at FROM recording_boundaries rb WHERE rb.workspace_id=g.workspace_id)"
                        if "recording_boundaries" in tables else "NULL")
            query = (f"SELECT g.*, {boundary} AS recording_started_at, {root} AS workspace_root, "
                     f"{initialized} AS initialization_recorded, {saved} AS settings_saved "
                     f"FROM ({query}) g {join}ORDER BY g.latest DESC")
            rows = conn.execute(query, (self.workspace_id,) if self.workspace_id else ()).fetchall()
        scopes = []
        for row in rows[:1000]:
            scope = dict(row)
            scope["initialization_recorded"] = bool(scope["initialization_recorded"])
            if scope["settings_saved"] is not None:
                scope["settings_saved"] = bool(scope["settings_saved"])
            # Database history cannot establish the current Plugin/Hook state.
            scope["runtime_state"] = "not_verified"
            scopes.append(scope)
        return {"scopes": scopes, "truncated": len(rows) > 1000,
                "fixed_workspace": self.workspace_id}

    def snapshot(self, *, workspace=(), session=(), blocked_only=False):
        if self.workspace_id is not None:
            workspace = self.workspace_id
        # Empty tuple means all; None deliberately selects unrecorded identity.
        clauses, params = [], []
        for column, value in (("workspace_id", workspace), ("session_id", session)):
            if value != ():
                if value is not None and (type(value) is not str or len(value) > 4096):
                    raise ValueError("invalid_scope")
                clauses.append(f"e.{column} IS ?")
                params.append(value)
        with closing(self.connect()) as conn:
            conn.execute("BEGIN")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
            forecasts = self.attach_forecasts(conn)
            cte = ""
            blocked = "0"
            if {"policy_decisions", "sink_candidates"} <= tables:
                cte = (
                    "WITH blocked_events AS (SELECT DISTINCT b.event_id,b.workspace_id,"
                    "b.session_id,b.tool_use_id FROM policy_decisions p "
                    "JOIN sink_candidates s ON p.sink_node_id=s.node_id "
                    "JOIN events b ON b.event_id=json_extract("
                    "CASE WHEN json_valid(s.metadata_json) THEN s.metadata_json ELSE '{}' END,"
                    "'$.event_id') AND b.sequence_no=s.sequence_no WHERE p.action='block') "
                )
                blocked = (
                    "EXISTS (SELECT 1 FROM blocked_events b WHERE b.event_id=e.event_id OR "
                    "(e.session_id IS NOT NULL AND e.session_id!='' AND "
                    "e.tool_use_id IS NOT NULL AND e.tool_use_id!='' AND "
                    "b.workspace_id IS e.workspace_id AND b.session_id=e.session_id "
                    "AND b.tool_use_id=e.tool_use_id))"
                )
            if forecasts:
                forecast_select = (
                    "SELECT b.event_id,b.workspace_id,b.session_id,b.tool_use_id "
                    "FROM forecast.requests r JOIN events b "
                    "ON b.event_id=json_extract(CASE WHEN json_valid(r.body) THEN r.body ELSE '{}' END,'$.structure.event') "
                    "AND b.workspace_id=r.workspace "
                    "AND b.session_id=json_extract(CASE WHEN json_valid(r.body) THEN r.body ELSE '{}' END,'$.structure.session') "
                    "WHERE r.application='additional_stop'"
                )
                if cte:
                    cte = cte[:-2] + " UNION " + forecast_select + ") "
                else:
                    cte = "WITH blocked_events AS (" + forecast_select + ") "
                    blocked = (
                        "EXISTS (SELECT 1 FROM blocked_events b WHERE b.event_id=e.event_id OR "
                        "(e.session_id IS NOT NULL AND e.session_id!='' AND "
                        "e.tool_use_id IS NOT NULL AND e.tool_use_id!='' AND "
                        "b.workspace_id IS e.workspace_id AND b.session_id=e.session_id "
                        "AND b.tool_use_id=e.tool_use_id))"
                    )
            if "semantic_flow_decisions" in tables:
                semantic_select = (
                    "SELECT b.event_id,b.workspace_id,b.session_id,b.tool_use_id "
                    "FROM semantic_flow_decisions d JOIN events b ON b.event_id=d.event_id "
                    "AND b.workspace_id=d.workspace_id AND b.session_id=d.session_id "
                    "WHERE d.action='block' AND b.phase='pre_tool_use'"
                )
                cte = (cte[:-2] + " UNION " + semantic_select + ") " if cte else
                       "WITH blocked_events AS (" + semantic_select + ") ")
                blocked = (
                    "EXISTS (SELECT 1 FROM blocked_events b WHERE b.event_id=e.event_id OR "
                    "(e.session_id IS NOT NULL AND e.session_id!='' AND "
                    "e.tool_use_id IS NOT NULL AND e.tool_use_id!='' AND "
                    "b.workspace_id IS e.workspace_id AND b.session_id=e.session_id "
                    "AND b.tool_use_id=e.tool_use_id))"
                )
            if blocked_only:
                if cte:
                    clauses.append(
                        "e.event_id IN (SELECT event_id FROM blocked_events UNION "
                        "SELECT related.event_id FROM blocked_events b JOIN events related "
                        "ON related.tool_use_id=b.tool_use_id AND related.workspace_id IS b.workspace_id "
                        "AND related.session_id=b.session_id "
                        "WHERE b.session_id!='' AND b.tool_use_id!='')"
                    )
                    blocked = "1"
                else:
                    clauses.append("0")
            clauses.append("e.tool_name IS NOT NULL AND e.tool_name!=''")
            rows = conn.execute(
                cte + f"SELECT {','.join('e.' + c.strip() for c in COLUMNS.split(','))}, "
                f"{blocked} AS is_blocked FROM events e WHERE {' AND '.join(clauses)} "
                "ORDER BY e.rowid DESC LIMIT 300", params,
            ).fetchall()
        calls = {}
        for row in rows:
            event = dict(row)
            is_blocked = bool(event.pop("is_blocked"))
            key = (event["workspace_id"], event["session_id"],
                   (event["tool_use_id"] if event["session_id"] else None) or event["event_id"])
            if key not in calls:
                calls[key] = event | {"phases": [], "blocked": is_blocked}
            calls[key]["phases"].append(event["phase"])
        return {"database": str(self.path), "calls": list(calls.values()), "window": 300}

    def graph(self, event_id):
        from tooluseproxy.graph_view import graph_snapshot
        with closing(self.connect()) as conn:
            conn.execute("BEGIN")
            return graph_snapshot(conn, event_id, self.workspace_id)

    def detail(self, event_id):
        with closing(self.connect()) as conn:
            conn.execute("BEGIN")
            selected = conn.execute(
                f"SELECT {COLUMNS} FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            if selected is None or (
                self.workspace_id is not None and selected["workspace_id"] != self.workspace_id
            ):
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
            events, decisions, judgments = [], [], []
            forecasts = self.attach_forecasts(conn)
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
                if "semantic_flow_decisions" in tables:
                    decisions.extend(dict(item) for item in conn.execute(
                        "SELECT event_id AS decision_id,action,'PreToolUse' AS hook_event,reason,"
                        "CASE WHEN reason='protected_content_match' THEN '保護内容との一致を検出し、実行前に停止' WHEN action='block' THEN '秘密情報源への依存経路を検出し、実行前に停止' "
                        "WHEN action='unavailable' THEN '情報流の判定未完了。流出検出ではありません' "
                        "ELSE '情報流グラフによる判定' END AS user_message,"
                        "recorded_at AS created_at,path_json FROM semantic_flow_decisions "
                        "WHERE event_id=? AND workspace_id=? AND session_id=?",
                        (event['event_id'], event['workspace_id'], event['session_id']),
                    ))
                if "pending_judgments" in tables:
                    judgment = conn.execute(
                        "SELECT event,state,attempts,result,held FROM pending_judgments "
                        "WHERE event=? AND workspace=?", (event["event_id"], event["workspace_id"])
                    ).fetchone()
                    if judgment:
                        judgments.append(dict(judgment))
                if forecasts:
                    decisions.extend({
                        "decision_id": item["id"], "action": "block", "hook_event": "PreToolUse",
                        "reason": "forecast_experimental_stop",
                        "user_message": "将来予測による追加停止（試験機能）。予測の有効性は未検証です。",
                        "created_at": None,
                    } for item in conn.execute(
                        "SELECT id FROM forecast.requests WHERE workspace=? AND application='additional_stop' "
                        "AND json_valid(body) AND json_extract(body,'$.structure.event')=? "
                        "AND json_extract(body,'$.structure.session')=? LIMIT 100",
                        (event["workspace_id"], event["event_id"], event["session_id"]),
                    ))
            return {"events": events, "decisions": decisions, "judgments": judgments, "event_limit": 50}


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
            if route in {"api/events", "api/detail", "api/scopes", "api/graph"}:
                try:
                    query = parse_qs(path.query, keep_blank_values=True)
                    with reader.access():
                        if route == "api/scopes":
                            result = reader.scopes()
                        elif route == "api/events":
                            filters = {}
                            for name in ("workspace", "session"):
                                if name in query:
                                    filters[name] = json.loads(query[name][0])
                            result = reader.snapshot(**filters, blocked_only=query.get("blocked") == ["1"])
                        elif route == "api/graph":
                            result = reader.graph(query.get("id", [""])[0])
                        else:
                            result = reader.detail(query.get("id", [""])[0])
                except (ValueError, TypeError):
                    status, result = 400, {"error": "絞り込み条件が不正です。"}
                except (sqlite3.Error, OSError):
                    status, result = 503, {"error": "DBに接続できません。保存先・権限・DBの状態を確認してください。"}
                body = json.dumps(result, ensure_ascii=False).encode()
                mime = "application/json; charset=utf-8"
            elif route in {"", "index.html", "screen.js", "screen.css", "graph.html", "graph.js", "graph.css", "theme.css"}:
                name = route or "index.html"
                body = (ASSETS / name).read_bytes()
                mime = {"index.html": "text/html; charset=utf-8", "screen.js": "text/javascript", "screen.css": "text/css", "graph.html": "text/html; charset=utf-8", "graph.js": "text/javascript", "graph.css": "text/css", "theme.css": "text/css"}[name]
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

    class LoopbackHTTPServer(ThreadingHTTPServer):
        def server_bind(self):
            # HTTPServer otherwise performs reverse DNS during bind. The viewer
            # only serves this numeric loopback address and needs no DNS name.
            TCPServer.server_bind(self)
            self.server_name, self.server_port = self.server_address[:2]

    server = LoopbackHTTPServer(("127.0.0.1", port), Handler)
    return server, f"http://127.0.0.1:{server.server_port}/{token}/"


def serve_workspace(db_path: Path, workspace: Path, *, as_json: bool = False) -> int:
    """Start a foreground viewer; never initialize or change protection settings."""
    from tooluseproxy.engine.workspace import make_workspace_id

    root = workspace.resolve(strict=True)
    reader = LogReader(db_path, make_workspace_id(str(root)), root)
    try:
        for name in ("index.html", "screen.js", "screen.css"):
            if not (ASSETS / name).is_file():
                raise OSError("viewer asset missing")
        with reader.access(), closing(reader.connect()) as conn:
            conn.execute("SELECT event_id FROM events LIMIT 0")
        server, url = make_server(reader)
    except (OSError, sqlite3.Error):
        result = {"status": "viewer_unavailable", "protection_changed": False,
                  "message": "ログUIを起動できませんでした。保護設定は変更していません。"}
        print(json.dumps(result, ensure_ascii=False) if as_json else result["message"], flush=True)
        return 1
    result = {"status": "ready", "url": url, "workspace_root": str(root),
              "workspace_id": reader.workspace_id, "protection_changed": False,
              "runtime_enforcement": "not_verified"}
    print(json.dumps(result, ensure_ascii=False) if as_json else f"ToolUseProxy ログ: {url}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


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
