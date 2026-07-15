from __future__ import annotations

from hook_monitor.policy.redaction_preview import RedactionPreviewPlan
from hook_monitor.runtime.models import (
    StoredRedactionPlan,
    StoredRedactionTarget,
)
from hook_monitor.runtime.storage import EventStore


def store_redaction_preview_plan(
    store: EventStore,
    plan: RedactionPreviewPlan,
) -> None:
    """Persist only hash-only plan metadata, never the rewrite candidate body."""
    targets = tuple(
        StoredRedactionTarget(
            plan_id=plan.plan_id,
            ordinal=target.ordinal,
            finding_id=target.finding_id,
            decision_id=target.decision_id,
            source_node_kind=target.source_node_kind,
            source_node_id=target.source_node_id,
            sink_node_id=target.sink_node_id,
            json_pointer=target.json_pointer,
            original_value_sha256=target.original_value_sha256,
            replacement_profile=target.replacement_profile,
        )
        for target in plan.targets
    )
    store.upsert_redaction_plan(
        StoredRedactionPlan(
            plan_id=plan.plan_id,
            analysis_run_id=plan.analysis_run_id,
            pre_event_id=plan.pre_event_id,
            workspace_id=plan.workspace_id,
            session_id=plan.session_id,
            tool_use_id=plan.tool_use_id,
            tool_name=plan.tool_name,
            adapter=plan.adapter,
            profile_id=plan.profile_id,
            profile_version=plan.profile_version,
            profile_registry_version=plan.profile_registry_version,
            mode=plan.mode,
            status=plan.status,
            planner_version=plan.planner_version,
            original_input_sha256=plan.original_input_sha256,
            rewritten_input_sha256=plan.rewritten_input_sha256,
            structure_sha256_before=plan.structure_sha256_before,
            structure_sha256_after=plan.structure_sha256_after,
            critical_finding_count=plan.critical_finding_count,
            replacement_count=plan.replacement_count,
            rejection_code=plan.rejection_code,
            post_event_id=None,
            targets=targets,
        )
    )
