"""Combine independent exact-content evidence and semantic provenance."""

from dataclasses import asdict

from tooluseproxy.engine.dlp import inspect_dlp, sources_unchanged
from tooluseproxy.engine.graph import digest
from tooluseproxy.engine.targets import inspect_transmission


def inspect_and_decide(store, event, sources, provider, graph_decision, node_id, model):
    def current_sources():
        return [
            dict(asdict(source), node_id="source:" + source.source_id)
            for source in store.list_protected_sources_for_workspace(event.workspace_id)
        ]

    def policy_key(values):
        return digest(sorted(values, key=lambda item: item["source_id"]))

    issues = ["payload_inspection_unavailable"]
    resolver = resolution = dlp = None
    try:
        resolver, resolution, _ = inspect_transmission(store, event, provider, model=model)
        dlp = inspect_dlp(resolver, resolution, sources)
        stable_policy = policy_key(sources) == policy_key(current_sources())
        if dlp.matches and stable_policy and resolver.unchanged(resolution):
            return dict(action="block", reason="protected_content_match", path=[], node_id=node_id)
        issues = list(dlp.issues)
        if resolution.coverage != "complete":
            issues.append("transmission_coverage_incomplete")
        if not stable_policy:
            issues.append("protection_policy_changed_during_inspection")
    except Exception:
        # This path cannot suppress an independently established graph block.
        pass
    result = graph_decision()
    if resolver is not None and resolution is not None and not resolver.unchanged(resolution):
        return dict(result, action="unavailable", reason="payload_changed_after_inspection")
    if result["action"] == "allow" and result["reason"] != "local_operation":
        if policy_key(sources) != policy_key(current_sources()):
            issues.append("protection_policy_changed_during_inspection")
        if resolver is not None and dlp is not None and not sources_unchanged(resolver, dlp):
            issues.append("protected_content_changed_during_inspection")
        if resolver is not None and resolution is not None and not resolver.unchanged(resolution):
            issues.append("payload_changed_after_inspection")
        if issues:
            result = dict(result, action="unavailable", reason=issues[0])
    return result
