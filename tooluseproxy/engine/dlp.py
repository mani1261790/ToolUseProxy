"""Exact-content evidence, independent of provenance and session boundaries.

The index stores keyed fingerprints, never protected plaintext. This is an exact
span detector, not proof that all paraphrases/short fragments are absent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.payload import ResolutionError, fingerprint, open_resource

SCHEME = "exact-spans-v1"
WIDTH = 64
STRIDE = 32
MIN_EXACT = 24


@dataclass
class DLPResult:
    matches: list[dict] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    source_observations: dict = field(default_factory=dict, repr=False)
    indexed_sources: int = 0
    reused_sources: int = 0


def informative(value):
    # Low-information/common short literals are insufficient for an automatic block.
    return len(value) >= MIN_EXACT and len(set(value)) >= 8


def spans(content):
    if not informative(content):
        return []
    if len(content) <= WIDTH:
        return [(0, content)]
    positions = list(range(0, len(content) - WIDTH + 1, STRIDE))
    if positions[-1] != len(content) - WIDTH:
        positions.append(len(content) - WIDTH)
    return [
        (offset, content[offset : offset + WIDTH])
        for offset in positions
        if informative(content[offset : offset + WIDTH])
    ]


def initialize(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_dlp_sources (
        scope TEXT NOT NULL, source TEXT NOT NULL, policy_key TEXT NOT NULL,
        fingerprint_json TEXT NOT NULL, content_version TEXT NOT NULL, eligible INTEGER NOT NULL,
        PRIMARY KEY(scope,source))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_dlp_spans (
        scope TEXT NOT NULL, source TEXT NOT NULL, offset INTEGER NOT NULL,
        length INTEGER NOT NULL, signature TEXT NOT NULL,
        PRIMARY KEY(scope,source,offset))""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS flow_dlp_signatures ON flow_dlp_spans(scope,length,signature)"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS flow_dlp_checks (
        scope TEXT NOT NULL, event TEXT NOT NULL, revision TEXT NOT NULL, result_json TEXT NOT NULL,
        PRIMARY KEY(scope,event,revision))""")


def inspect_dlp(resolver, resolution, sources, *, max_hashes=2_000_000):
    result = DLPResult()
    ledger, scope = resolver.store, resolver.scope
    with ledger.transaction() as conn:
        initialize(conn)
    active = set()
    expected = {}
    source_budget = {"bytes": 8_388_608}
    for source in sources:
        source_id = source["source_id"]
        selector = source.get("selector")
        if selector and (not isinstance(selector, dict) or selector.get("kind") != "whole_file"):
            result.issues.append("unsupported_source_selector")
            continue
        path = source.get("path")
        policy_key = digest([SCHEME, path, selector])
        try:
            with open_resource(resolver.root, path) as (descriptor, _, __):
                import os

                stamp = fingerprint(os.fstat(descriptor))
            with ledger.transaction() as conn:
                cached = conn.execute(
                    "SELECT policy_key,fingerprint_json,eligible FROM flow_dlp_sources WHERE scope=? AND source=?",
                    (scope, source_id),
                ).fetchone()
            if cached and cached[0] == policy_key and json.loads(cached[1]) == stamp:
                eligible = bool(cached[2])
                result.reused_sources += 1
            else:
                content, evidence = resolver.read_file(path, source_budget)
                selected = spans(content)
                eligible = bool(selected)
                with ledger.transaction() as conn:
                    conn.execute(
                        "DELETE FROM flow_dlp_spans WHERE scope=? AND source=?", (scope, source_id)
                    )
                    conn.executemany(
                        "INSERT INTO flow_dlp_spans VALUES (?,?,?,?,?)",
                        [
                            (scope, source_id, offset, len(value), resolver.token(value))
                            for offset, value in selected
                        ],
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO flow_dlp_sources VALUES (?,?,?,?,?,?)",
                        (
                            scope,
                            source_id,
                            policy_key,
                            json.dumps(evidence["fingerprint"]),
                            resolver.token(content),
                            int(eligible),
                        ),
                    )
                result.indexed_sources += 1
                stamp = evidence["fingerprint"]
            if eligible:
                active.add(source_id)
                expected[source_id] = (path, stamp)
            else:
                result.limitations.append("source_has_no_distinctive_exact_span")
        except (OSError, ResolutionError, TypeError):
            result.issues.append("protected_content_unavailable")

    # Inactive/removed registrations must not contribute stale matches.
    with ledger.transaction() as conn:
        rows = conn.execute(
            "SELECT p.source,p.offset,p.length,p.signature,s.fingerprint_json FROM flow_dlp_spans p JOIN flow_dlp_sources s ON s.scope=p.scope AND s.source=p.source WHERE p.scope=?",
            (scope,),
        ).fetchall()
    signatures = {}
    for source, offset, length, signature, stamp in rows:
        if source in active and json.loads(stamp) == expected[source][1]:
            signatures.setdefault(length, {}).setdefault(signature, []).append((source, offset))
    remaining = max_hashes
    seen = set()
    for part in resolution.parts:
        for width, lookup in signatures.items():
            for offset in range(max(0, len(part.content) - width + 1)):
                if remaining <= 0:
                    result.issues.append("dlp_work_budget")
                    break
                remaining -= 1
                signature = resolver.token(part.content[offset : offset + width])
                for source, source_offset in lookup.get(signature, []):
                    key = (source, part.version.identity)
                    if key in seen:
                        continue
                    seen.add(key)
                    result.matches.append(
                        dict(
                            source_id=source,
                            source_offset=source_offset,
                            payload_version=part.version.identity,
                            payload_offset=offset,
                            length=width,
                            method="exact_content_span",
                        )
                    )
            if remaining <= 0:
                break
        if remaining <= 0:
            break
    result.source_observations = expected
    changed_sources = set()
    for source, (path, stamp) in expected.items():
        try:
            with open_resource(resolver.root, path) as (descriptor, _, __):
                if fingerprint(os.fstat(descriptor)) != stamp:
                    changed_sources.add(source)
        except (OSError, ResolutionError):
            changed_sources.add(source)
    if changed_sources:
        result.matches = [
            match for match in result.matches if match["source_id"] not in changed_sources
        ]
        result.issues.append("protected_content_changed_during_inspection")
    if not resolver.unchanged(resolution):
        # The match describes an obsolete snapshot; require another inspection.
        result.matches.clear()
        result.issues.append("payload_changed_after_inspection")
    record = dict(
        matches=result.matches,
        issues=sorted(set(result.issues)),
        scheme=SCHEME,
        limitations=sorted(set(result.limitations)),
        coverage=resolution.coverage,
        indexed=result.indexed_sources,
        reused=result.reused_sources,
    )
    revision = digest(
        [
            resolver.event,
            record,
            [(part.version.identity, part.extent) for part in resolution.parts],
            sorted(active),
        ]
    )
    with ledger.transaction() as conn:
        conn.execute(
            "INSERT INTO flow_dlp_checks VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
            (scope, resolver.event, revision, json.dumps(record)),
        )
    return result


def sources_unchanged(resolver, result):
    import os

    for path, stamp in result.source_observations.values():
        try:
            with open_resource(resolver.root, path) as (descriptor, _, __):
                if fingerprint(os.fstat(descriptor)) != stamp:
                    return False
        except (OSError, ResolutionError):
            return False
    return True
