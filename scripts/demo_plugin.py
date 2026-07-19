#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DOGFOOD_RUNNER = REPO_ROOT / "scripts" / "dogfood_plugin.py"
DEMO_LIMIT_MS = 30_000.0
REQUIRED_CHECKS = (
    "candidate_rejected",
    "candidate_ignored",
    "candidate_approved",
    "negative_reviews_suppressed",
    "public_bash_allowed",
    "protected_bash_denied",
    "stop_continue_review",
    "runtime_data_deleted_after_confirmation",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the ToolUseProxy 30-second synthetic Plugin preview.",
    )
    parser.add_argument("--json", action="store_true", help="Print aggregate JSON.")
    args = parser.parse_args()

    started_at = time.monotonic()
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(DOGFOOD_RUNNER),
                "--installation-mode",
                "extracted",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return _render_failure(args.json, "demo_deadline_exceeded")
    elapsed_ms = round((time.monotonic() - started_at) * 1000, 3)
    if result.returncode != 0:
        return _render_failure(args.json, "dogfood_failed")
    try:
        dogfood = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _render_failure(args.json, "dogfood_output_invalid")
    if (
        not isinstance(dogfood, dict)
        or dogfood.get("schema_version") != 2
        or dogfood.get("status") != "passed"
    ):
        return _render_failure(args.json, "dogfood_status_invalid")
    checks = dogfood.get("checks")
    metrics = dogfood.get("metrics")
    if not isinstance(checks, dict) or not isinstance(metrics, dict):
        return _render_failure(args.json, "dogfood_contract_invalid")
    if any(checks.get(name) is not True for name in REQUIRED_CHECKS):
        return _render_failure(args.json, "required_check_failed")
    if checks.get("raw_value_exposure") is not False:
        return _render_failure(args.json, "raw_value_exposure")
    if metrics.get("external_side_effect_count") != 0:
        return _render_failure(args.json, "external_side_effect_detected")
    plugin_version = dogfood.get("plugin_version")
    artifact_sha256 = dogfood.get("artifact_sha256")
    if (
        not isinstance(plugin_version, str)
        or not plugin_version
        or not isinstance(artifact_sha256, str)
        or len(artifact_sha256) != 64
        or any(character not in "0123456789abcdef" for character in artifact_sha256)
    ):
        return _render_failure(args.json, "artifact_identity_invalid")
    if elapsed_ms > DEMO_LIMIT_MS:
        return _render_failure(args.json, "demo_deadline_exceeded")

    payload = {
        "schema_version": 1,
        "status": "passed",
        "demo_kind": "automated_phase_a_preview",
        "elapsed_ms": elapsed_ms,
        "limit_ms": DEMO_LIMIT_MS,
        "plugin_version": plugin_version,
        "artifact_sha256": artifact_sha256,
        "checks": {
            "explicit_candidate_decisions": True,
            "negative_review_suppression": True,
            "public_call_allowed": True,
            "protected_call_denied": True,
            "final_answer_reviewed": True,
            "managed_data_deleted_after_confirmation": True,
            "external_side_effect_count": 0,
            "raw_value_exposure": False,
        },
        "manual_trust_evidence": "not_included_run_manual_phase_b",
    }
    print(json.dumps(payload, sort_keys=True) if args.json else _render_text(payload))
    return 0


def _render_failure(as_json: bool, code: str) -> int:
    payload = {
        "schema_version": 1,
        "status": "failed",
        "error_code": code,
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"ToolUseProxy demo failed: {code}", file=sys.stderr)
    return 1


def _render_text(payload: dict[str, Any]) -> str:
    elapsed_seconds = float(payload["elapsed_ms"]) / 1000
    version = payload["plugin_version"]
    return "\n".join(
        (
            f"ToolUseProxy {version} — 30-second synthetic Plugin preview",
            f"Completed in {elapsed_seconds:.2f}s.",
            "✓ Built a clean relocatable Plugin artifact.",
            "✓ Reviewed approve, reject, and ignore candidate decisions.",
            "✓ Allowed a public call and denied a protected call.",
            "✓ Reviewed a protected final answer without exposing the canary.",
            "✓ Removed Plugin code, retained data, then deleted managed data after confirmation.",
            "External side effects: 0. Raw value exposure: 0.",
            "This is automated Phase A; Hook trust and actual tool execution require manual Phase B.",
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
