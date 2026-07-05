from __future__ import annotations

from hook_monitor.policy.models import PolicyDecision


_ACTION_ORDER = {
    "block": 0,
    "continue_review": 1,
    "redact": 2,
    "warn": 3,
    "allow": 4,
}


def select_strongest_decision(
    decisions: list[PolicyDecision],
    hook_event: str,
) -> PolicyDecision | None:
    eligible = [
        decision
        for decision in decisions
        if decision.hook_event == hook_event
        or _can_project_decision_to_hook(decision, hook_event)
    ]
    if not eligible:
        return None
    return sorted(eligible, key=_decision_sort_key)[0]


def render_codex_hook_output(
    decision: PolicyDecision | None,
    hook_event: str,
) -> dict[str, object]:
    if decision is None or decision.action == "allow":
        return {}
    if decision.action == "redact":
        raise NotImplementedError("redact requires tool-specific updatedInput handling")
    if hook_event == "PreToolUse":
        return _render_pre_tool_use(decision)
    if hook_event == "PermissionRequest":
        return _render_permission_request(decision)
    if hook_event == "PostToolUse":
        return _render_post_tool_use(decision)
    if hook_event == "Stop":
        return _render_stop(decision)
    raise ValueError(f"unsupported Codex hook event: {hook_event}")


def _can_project_decision_to_hook(
    decision: PolicyDecision,
    hook_event: str,
) -> bool:
    if decision.sink_type.startswith("external_"):
        return hook_event in {"PreToolUse", "PermissionRequest", "PostToolUse"}
    if decision.sink_type == "final_answer":
        return hook_event == "Stop"
    return False


def _render_pre_tool_use(decision: PolicyDecision) -> dict[str, object]:
    if decision.action == "block":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": _message(decision),
            }
        }
    if decision.action == "warn":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": _message(decision),
            }
        }
    return {}


def _render_permission_request(decision: PolicyDecision) -> dict[str, object]:
    if decision.action == "block":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": _message(decision),
                },
            }
        }
    if decision.action == "allow":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "allow"},
            }
        }
    return {}


def _render_post_tool_use(decision: PolicyDecision) -> dict[str, object]:
    if decision.action == "block":
        message = _message(decision)
        return {
            "decision": "block",
            "reason": message,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": message,
            },
        }
    if decision.action == "warn":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": _message(decision),
            }
        }
    return {}


def _render_stop(decision: PolicyDecision) -> dict[str, object]:
    if decision.action == "continue_review":
        return {
            "decision": "block",
            "reason": _message(decision),
        }
    if decision.action == "warn":
        return {
            "systemMessage": _message(decision),
        }
    return {}


def _message(decision: PolicyDecision) -> str:
    return (
        f"{decision.reason}. source={decision.source_node_kind}:{decision.source_node_id} "
        f"sink=sink_candidate:{decision.sink_node_id} score={decision.path_score:.2f}"
    )


def _decision_sort_key(decision: PolicyDecision) -> tuple[int, float, str, str]:
    return (
        _ACTION_ORDER.get(decision.action, 9),
        -decision.path_score,
        decision.source_node_id,
        decision.sink_node_id,
    )
