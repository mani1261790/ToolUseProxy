from __future__ import annotations

import json
import pytest

from scripts.build_exhibition_replay import export_replay


def evidence():
    return {
        "status": "passed", "demo_kind": "automated_phase_a_preview",
        "plugin_version": "0.1.0-alpha.24", "artifact_sha256": "a" * 64,
        "checks": {"public_call_allowed": True, "protected_call_denied": True,
                   "raw_value_exposure": False, "external_side_effect_count": 0},
    }


def test_export_does_not_copy_raw_data_or_invent_receiver_evidence():
    report = evidence()
    report["private_source"] = "SYNTHETIC_DO_NOT_DISPLAY"
    report["checks"]["diagnostic"] = "/private/artificial/path"
    result = export_replay(report)
    serialized = json.dumps(result, ensure_ascii=False)
    assert "SYNTHETIC_DO_NOT_DISPLAY" not in serialized
    assert "/private/artificial/path" not in serialized
    assert result["receiver"] == "not_observed"
    assert result["mode"] == "synthetic_replay"
    assert result["scenarios"][2]["kind"] == "説明用の人工例（試験結果ではありません）"


@pytest.mark.parametrize("key,value", [
    ("public_call_allowed", False), ("protected_call_denied", False),
    ("raw_value_exposure", True), ("external_side_effect_count", 1),
    ("public_call_allowed", "true"), ("external_side_effect_count", False),
])
def test_failed_or_incomplete_evidence_cannot_be_displayed_as_success(key, value):
    report = evidence()
    report["checks"][key] = value
    with pytest.raises(ValueError):
        export_replay(report)


@pytest.mark.parametrize("key,value", [
    ("plugin_version", "<script>alert('fixture')</script>"),
    ("artifact_sha256", "/private/fixture"), ("status", "failed"),
])
def test_untrusted_identity_is_rejected(key, value):
    report = evidence()
    report[key] = value
    with pytest.raises(ValueError):
        export_replay(report)
