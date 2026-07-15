from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from hook_monitor.policy.engine import make_policy_decision_id


REDACTION_DECISION_DERIVATION_VERSION = "mcp-redact-decision-v1"
_LOWER_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class DerivedRedactDecision:
    finding_id: str
    source_block_decision_id: str
    derived_redact_decision_id: str
    derivation_version: str = REDACTION_DECISION_DERIVATION_VERSION


def derive_redact_decision(
    *,
    finding_id: str,
    source_block_decision_id: str,
) -> DerivedRedactDecision:
    """Derive one dormant REDACT identity from its critical BLOCK decision."""
    if _LOWER_SHA256_RE.fullmatch(finding_id) is None:
        raise ValueError("redact decision finding id must be a lowercase SHA-256")
    expected_block_decision_id = make_policy_decision_id(
        finding_id,
        "block",
        "PreToolUse",
    )
    if source_block_decision_id != expected_block_decision_id:
        raise ValueError("redact decision source is not the finding's block decision")
    encoded = json.dumps(
        [
            "tooluseproxy:derived-redact-decision:v1",
            REDACTION_DECISION_DERIVATION_VERSION,
            source_block_decision_id,
            "redact",
            "PreToolUse",
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return DerivedRedactDecision(
        finding_id=finding_id,
        source_block_decision_id=source_block_decision_id,
        derived_redact_decision_id=hashlib.sha256(encoded).hexdigest(),
    )
