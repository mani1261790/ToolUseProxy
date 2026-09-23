"""Experimental candidate retrieval, excluded from the shipped policy engine.

The index contains only recorded observations, scoped to a workspace/session.
Resource witnesses and explicitly selected observations are mandatory candidates;
recent and lexical retrieval supplement them. Semantic recall remains empirical.
"""

from __future__ import annotations

import re
from collections import Counter

from tooluseproxy.engine.graph import GraphUnavailable, digest

VERSION = "recent-resource-lexical-v1"
RECENT = 5
RETRIEVED = 8


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def terms(node):
    # Japanese does not separate words with spaces. Character bigrams provide
    # local lexical retrieval without downloading a tokenizer or calling a model.
    values = [node.get("input"), node.get("required_output", node.get("output")),
              [part.get("content") for part in node.get("payload_observations", [])],
              [part.get("path") for part in node.get("resource_observations", [])]]
    found = set()
    for text in strings(values):
        found.update(re.findall(r"[a-z0-9_]{2,}", text.lower()))
        for run in re.findall(r"[\u3040-\u30ff\u3400-\u9fff]+", text):
            found.update(run[i:i+2] for i in range(len(run)-1))
    return found


class CandidateIndex:
    def __init__(self, conn, workspace, session, calls):
        self.conn, self.calls = conn, calls
        self.scope = digest([workspace, session, VERSION, calls[0]["node_id"] if calls else None])
        self.frequency = Counter()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS flow_candidate_documents (
                id INTEGER PRIMARY KEY, scope TEXT NOT NULL, node TEXT NOT NULL,
                fingerprint TEXT NOT NULL, position INTEGER NOT NULL,
                UNIQUE(scope,node));
            CREATE VIRTUAL TABLE IF NOT EXISTS flow_candidate_search USING fts5(
                terms, scope UNINDEXED, node UNINDEXED, position UNINDEXED);
        """)
        with conn:
            for position, node in enumerate(calls):
                if not node["completed"]:
                    continue
                tokens = terms(node)
                self.frequency.update(tokens)
                fingerprint = digest([node["input"], node["output"], sorted(tokens)])
                old = conn.execute("SELECT id,fingerprint,position FROM flow_candidate_documents WHERE scope=? AND node=?",
                                   (self.scope, node["node_id"])).fetchone()
                if old and old[1] == fingerprint:
                    if old[2] != position:
                        conn.execute("UPDATE flow_candidate_documents SET position=? WHERE id=?", (position, old[0]))
                        conn.execute("UPDATE flow_candidate_search SET position=? WHERE rowid=?", (position, old[0]))
                    continue
                conn.execute("INSERT INTO flow_candidate_documents(scope,node,fingerprint,position) VALUES (?,?,?,?) "
                             "ON CONFLICT(scope,node) DO UPDATE SET fingerprint=excluded.fingerprint,position=excluded.position",
                             (self.scope, node["node_id"], fingerprint, position))
                rowid = conn.execute("SELECT id FROM flow_candidate_documents WHERE scope=? AND node=?",
                                     (self.scope, node["node_id"])).fetchone()[0]
                conn.execute("DELETE FROM flow_candidate_search WHERE rowid=?", (rowid,))
                conn.execute("INSERT INTO flow_candidate_search(rowid,terms,scope,node,position) VALUES (?,?,?,?,?)",
                             (rowid, " ".join(sorted(tokens)), self.scope, node["node_id"], position))

    def select(self, index, current):
        prior = {n["node_id"]: n for n in self.calls[:index] if n["completed"]}
        reasons = {}

        def add(node, reason):
            if node in prior:
                reasons.setdefault(node, []).append(reason)

        for node in list(prior)[-RECENT:]:
            add(node, "recent")
        for part in current.get("payload_observations", []):
            node = part.get("observation", {}).get("source_node_id")
            if node is not None:
                if node not in prior:
                    raise GraphUnavailable("observed_transmission_parent_missing")
                add(node, "observed_value")
        origins = {item["producer_event"] for item in current.get("resource_origins", [])}
        for node, record in prior.items():
            if record["event_id"] in origins:
                add(node, "resource_generation")
        # Rare recorded terms first; quoting prevents input from becoming FTS syntax.
        tokens = sorted((t for t in terms(current) if self.frequency[t]),
                        key=lambda t: (self.frequency[t], t))[:64]
        if tokens:
            query = " OR ".join('"' + token + '"' for token in tokens)
            rows = self.conn.execute(
                "SELECT node FROM flow_candidate_search WHERE flow_candidate_search MATCH ? "
                "AND scope=? AND CAST(position AS INTEGER)<? ORDER BY bm25(flow_candidate_search), "
                "CAST(position AS INTEGER) DESC LIMIT ?", (query, self.scope, index, RETRIEVED))
            for (node,) in rows:
                add(node, "lexical_retrieval")
        selected = [node for node in prior.values() if node["node_id"] in reasons]
        scope = dict(kind="retrieved", version=VERSION, prior_count=len(prior),
                     selected_count=len(selected), recent_limit=RECENT, retrieval_limit=RETRIEVED,
                     exhaustive=len(selected) == len(prior), reasons=reasons)
        return dict(current_call=current, previous_calls=selected, history_scope=scope)
