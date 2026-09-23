"""Link sessions only through witnessed resource generations, never path names alone."""

from __future__ import annotations

import json

from tooluseproxy.engine.evidence import EvidenceStore, EvidenceNeed
from tooluseproxy.engine.payload import PayloadResolver, ResolutionError


def schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_operation_plans (
        scope TEXT NOT NULL, session TEXT NOT NULL, call_id TEXT NOT NULL,
        event TEXT NOT NULL, resources_json TEXT NOT NULL,
        PRIMARY KEY(scope,session,call_id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_file_observations (
        observation INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL, event TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL,
        mode TEXT NOT NULL, status TEXT NOT NULL, fingerprint_json TEXT NOT NULL,
        UNIQUE(scope,event,path,mode,version,fingerprint_json))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_immutable_reads (
        scope TEXT NOT NULL,event TEXT NOT NULL,path TEXT NOT NULL,version TEXT NOT NULL,
        PRIMARY KEY(scope,event,path,version))""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS flow_generation_lookup ON flow_file_observations(scope,path,version,fingerprint_json,mode,status)"
    )


def snapshot_resources(store, event, resources=None):
    ledger = EvidenceStore(store.db_path)
    ledger.initialize()
    with ledger.transaction() as conn:
        schema(conn)
        row = conn.execute(
            "SELECT workspace_root FROM events WHERE event_id=? AND workspace_id=?",
            (event.event_id, event.workspace_id),
        ).fetchone()
        if not row:
            return
        if event.phase == "pre_tool_use":
            normalized = []
            for item in (resources or [])[:64]:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"path", "mode"}
                    or item["mode"] not in ("read", "write")
                ):
                    continue
                try:
                    from tooluseproxy.engine.requirements import resource_identity
                    item = dict(item, path=resource_identity(item["path"], row[0]))
                except (ResolutionError, ValueError, OSError):
                    continue
                normalized.append(item)
            conn.execute(
                "INSERT INTO flow_operation_plans VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
                (
                    event.workspace_id,
                    event.session_id,
                    event.tool_use_id,
                    event.event_id,
                    json.dumps(normalized),
                ),
            )
            plan_event = event.event_id
        else:
            plan = conn.execute(
                "SELECT event,resources_json FROM flow_operation_plans WHERE scope=? AND session=? AND call_id=?",
                (event.workspace_id, event.session_id, event.tool_use_id),
            ).fetchone()
            if not plan:
                return
            plan_event, raw = plan
            normalized = json.loads(raw)
            response = event.raw_payload.get("tool_response")
            if event.raw_payload.get("is_error") is True or (
                isinstance(response, dict)
                and (
                    response.get("is_error") is True
                    or response.get("exit_code", 0) not in (0, None)
                )
            ):
                return
    resolver = PayloadResolver(ledger, event.workspace_id, event.event_id, row[0])
    budget = {"bytes": 4_194_304}
    for item in normalized:
        if event.phase == "pre_tool_use" and item["mode"] != "read":
            continue
        try:
            external = item["path"].startswith("/")
            if external:
                from tooluseproxy.engine.requirements import external_generation
                stamp = json.dumps(external_generation(item["path"]))
                content = ("metadata-generation:" + stamp).encode()
            else:
                content, observation = resolver.read_file(item["path"], budget)
                stamp = json.dumps(observation["fingerprint"])
            if event.phase == "post_tool_use" and item["mode"] == "read":
                with ledger.transaction() as conn:
                    before = conn.execute(
                        "SELECT fingerprint_json FROM flow_file_observations WHERE scope=? AND event=? AND path=? AND mode=? ORDER BY observation DESC LIMIT 1",
                        (event.workspace_id, plan_event, item["path"], "read"),
                    ).fetchone()
                if not before or before[0] != stamp:
                    continue
            from tooluseproxy.engine.evidence import ContentVersion, Resource

            value = ContentVersion(
                Resource(event.workspace_id, "file", item["path"]),
                resolver.token(content),
                event.event_id,
                len(content),
            )
            ledger.add_version(value)
            status = "observed" if event.phase == "post_tool_use" else "planned"
            ledger.add_access(
                value,
                item["mode"],
                status,
                "inference",
                {"metadata_only": True} if external else {"whole": True},
                "declared access with metadata generation" if external else "declared access with controller snapshot",
            )
            with ledger.transaction() as conn:
                conn.execute(
                    "INSERT INTO flow_file_observations(scope,event,path,version,mode,status,fingerprint_json) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                    (
                        event.workspace_id,
                        event.event_id,
                        item["path"],
                        value.identity,
                        item["mode"],
                        status,
                        stamp,
                    ),
                )
        except (OSError, ValueError):
            ledger.add_need(
                event.workspace_id,
                event.event_id,
                EvidenceNeed("resource_version", item["path"], "access_snapshot_unavailable"),
            )
            continue


def record_transmission_snapshots(resolver, result):
    with resolver.store.transaction() as conn:
        schema(conn)
        conn.execute("DELETE FROM flow_immutable_reads WHERE scope=? AND event=?",
                     (resolver.scope, resolver.event))
    # Bind committed blob bytes to the same path/content generation as a prior
    # file observation, without claiming that the working tree still has them.
    aliases = []
    for part in result.parts:
        if part.version.resource.kind == "repository_object" and part.observation["object_kind"] == "blob":
            from pathlib import PurePosixPath
            from tooluseproxy.engine.evidence import ContentVersion, Resource
            for path in part.observation["paths"]:
                path = str(PurePosixPath(part.observation["repository"]) / path)
                value = ContentVersion(Resource(resolver.scope, "file", path),
                                       part.version.token, resolver.event, len(part.content))
                resolver.store.add_version(value)
                try:
                    current, observation = resolver.read_file(path, {"bytes": resolver.max_bytes})
                    matches_current = resolver.token(current) == part.version.token
                except (OSError, ValueError):
                    matches_current = False
                with resolver.store.transaction() as conn:
                    schema(conn)
                    conn.execute("INSERT OR IGNORE INTO flow_immutable_reads VALUES (?,?,?,?)",
                                 (resolver.scope, resolver.event, path, value.identity))
                if not matches_current:
                    # The immutable bytes still identify the recorded version.
                    # Preserve that identity separately from a live inode stamp.
                    aliases.append((path, value.identity, json.dumps(part.observation)))
                    continue
                aliases.append((path, value.identity, json.dumps(observation["fingerprint"])))
    with resolver.store.transaction() as conn:
        schema(conn)
        for path, version, evidence in aliases:
            conn.execute(
                "INSERT INTO flow_file_observations(scope,event,path,version,mode,status,fingerprint_json) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                (resolver.scope, resolver.event, path, version, "read", "planned", evidence))
        for part in result.parts:
            if part.version.resource.kind == "file":
                conn.execute(
                    "INSERT INTO flow_file_observations(scope,event,path,version,mode,status,fingerprint_json) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                    (
                        resolver.scope,
                        resolver.event,
                        part.version.resource.locator,
                        part.version.identity,
                        "read",
                        "planned",
                        json.dumps(part.observation["fingerprint"]),
                    ),
                )


def matching_producers(conn, workspace, event):
    schema(conn)
    boundary = 0
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='recording_boundaries'").fetchone():
        row = conn.execute(
            "SELECT after_sequence FROM recording_boundaries WHERE workspace_id=?", (workspace,)
        ).fetchone()
        boundary = row[0] if row else 0
    live = conn.execute(
        """SELECT DISTINCT p.event,pe.session_id,p.path,p.version
        FROM flow_file_observations c JOIN events ce ON ce.event_id=c.event
        JOIN flow_file_observations p ON p.scope=c.scope AND p.path=c.path
          AND p.version=c.version AND p.fingerprint_json=c.fingerprint_json
        JOIN events pe ON pe.event_id=p.event
        WHERE c.scope=? AND c.event=? AND c.mode='read'
          AND c.observation=(SELECT MAX(last.observation) FROM flow_file_observations last WHERE last.scope=c.scope AND last.event=c.event AND last.path=c.path AND last.mode=c.mode)
          AND p.observation=(SELECT MAX(last.observation) FROM flow_file_observations last WHERE last.scope=p.scope AND last.event=p.event AND last.path=p.path AND last.mode=p.mode)
          AND pe.sequence_no>?
          AND p.mode='write' AND p.status='observed' AND pe.sequence_no<ce.sequence_no
          AND NOT EXISTS (SELECT 1 FROM flow_file_observations newer JOIN events ne ON ne.event_id=newer.event
             WHERE newer.scope=p.scope AND newer.path=p.path AND newer.mode='write' AND newer.status='observed'
             AND ne.sequence_no>pe.sequence_no AND ne.sequence_no<ce.sequence_no)
        ORDER BY pe.sequence_no DESC""",
        (workspace, event, boundary),
    ).fetchall()
    immutable = conn.execute(
        """SELECT DISTINCT p.event,pe.session_id,p.path,p.version
        FROM flow_immutable_reads c JOIN events ce ON ce.event_id=c.event
        JOIN flow_file_observations p ON p.scope=c.scope AND p.path=c.path AND p.version=c.version
        JOIN events pe ON pe.event_id=p.event
        WHERE c.scope=? AND c.event=? AND p.mode='write' AND p.status='observed'
          AND pe.sequence_no>? AND pe.sequence_no<ce.sequence_no
        ORDER BY pe.sequence_no DESC""", (workspace,event,boundary)).fetchall()
    # A model still establishes the consumer's read and each producer's ancestry.
    # Matching immutable resource identity is evidence, not a similarity edge.
    return list(dict.fromkeys([*live, *immutable]))


def attach_witnesses(conn, workspace, node):
    schema(conn)
    rows = conn.execute(
        """SELECT o.path,o.version,o.mode,o.status,o.fingerprint_json FROM flow_file_observations o
        WHERE o.scope=? AND o.event=? AND o.observation=(SELECT MAX(last.observation) FROM flow_file_observations last
        WHERE last.scope=o.scope AND last.event=o.event AND last.path=o.path AND last.mode=o.mode)
        ORDER BY o.path,o.mode""",
        (workspace, node["event_id"]),
    ).fetchall()
    if rows:
        node["resource_observations"] = [
            dict(
                path=path, version=version, mode=mode, status=status, fingerprint=json.loads(stamp)
            )
            for path, version, mode, status, stamp in rows
        ]
        origins = []
        for event, _, path, version in matching_producers(conn, workspace, node["event_id"]):
            origins.append(
                # A model result is not an observation. Including the mutable
                # graph head here invalidated history caches whenever a parent
                # was analyzed, even though no ToolCall evidence had changed.
                dict(path=path, version=version, producer_event=event)
            )
        node["resource_origins"] = origins
