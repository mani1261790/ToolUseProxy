#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
STAGE_TIMEOUT_SECONDS = 900


class AutomatedDogfoodFailure(RuntimeError):
    def __init__(self, stage: str, code: str) -> None:
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}: {code}")


@dataclass(frozen=True)
class Stage:
    name: str
    command: tuple[str, ...]
    report_kind: str | None = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run every repeatable ToolUseProxy release check once and emit a "
            "value-free aggregate report."
        )
    )
    parser.add_argument(
        "--installation-mode",
        choices=("codex", "extracted"),
        default="codex",
        help=(
            "Use an isolated Codex marketplace for lifecycle checks, or test "
            "extracted artifacts when the Codex CLI is unavailable."
        ),
    )
    parser.add_argument(
        "--skip-quality",
        action="store_true",
        help="Skip ruff, pytest, and git diff checks. Intended for runner tests only.",
    )
    args = parser.parse_args(argv)

    try:
        report = run_all(
            installation_mode=args.installation_mode,
            include_quality=not args.skip_quality,
        )
    except AutomatedDogfoodFailure as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "stage": error.stage,
                    "error_code": error.code,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


def run_all(*, installation_mode: str, include_quality: bool) -> dict[str, Any]:
    started = time.monotonic()
    python = sys.executable
    stages: list[Stage] = []
    if include_quality:
        stages.extend(
            (
                Stage("ruff", (python, "-m", "ruff", "check", ".")),
                Stage(
                    "pytest",
                    (
                        python,
                        "-m",
                        "pytest",
                        "-q",
                        "--ignore=tests/test_plugin_dogfood.py",
                        "--ignore=tests/test_externality_dogfood.py",
                        "--ignore=tests/test_plugin_lifecycle_rehearsal.py",
                        "--ignore=tests/test_automated_dogfood.py",
                    ),
                ),
                Stage("diff_check", ("git", "diff", "--check")),
            )
        )
    stages.extend(
        (
            Stage(
                "plugin_workflow",
                (
                    python,
                    "scripts/dogfood_plugin.py",
                    "--installation-mode",
                    installation_mode,
                ),
                "plugin",
            ),
            Stage(
                "externality_protection",
                (python, "scripts/dogfood_externality.py"),
                "externality",
            ),
            Stage(
                "upgrade_rollback_remove",
                (
                    python,
                    "scripts/rehearse_plugin_lifecycle.py",
                    "--installation-mode",
                    installation_mode,
                ),
                "lifecycle",
            ),
        )
    )

    stage_reports: dict[str, dict[str, Any]] = {}
    for stage in stages:
        stage_started = time.monotonic()
        try:
            result = subprocess.run(
                stage.command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=STAGE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise AutomatedDogfoodFailure(stage.name, "command_timed_out") from error
        if result.returncode != 0:
            raise AutomatedDogfoodFailure(stage.name, "command_failed")
        summary: dict[str, Any] = {
            "status": "passed",
            "duration_ms": round((time.monotonic() - stage_started) * 1000, 3),
        }
        if stage.report_kind is not None:
            payload = _parse_child_report(stage.name, result.stdout)
            summary.update(_validate_child_report(stage.report_kind, payload))
        stage_reports[stage.name] = summary

    revision = _read_revision()
    return {
        "schema_version": 1,
        "status": "passed",
        "source_revision": revision,
        "installation_mode": installation_mode,
        "automated": {
            "status": "passed",
            "all_repeatable_checks_passed": True,
            "stages": stage_reports,
        },
        "desktop": {
            "status": "human_required",
            "reason": "codex_desktop_self_control_is_blocked",
            "remaining_actions": [
                "review_and_trust_three_tooluseproxy_hooks",
                "open_the_generated_desktop_task",
                "decide_two_scoped_approval_requests",
            ],
            "automated_after_task": [
                "collect_value_free_evidence",
                "verify_public_allow_and_protected_pre_execution_block",
                "verify_raw_exposure_zero",
                "generate_report_and_cleanup_plan",
            ],
        },
        "metrics": {
            "automated_stage_count": len(stages),
            "total_duration_ms": round((time.monotonic() - started) * 1000, 3),
        },
    }


def _parse_child_report(stage: str, stdout: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise AutomatedDogfoodFailure(stage, "json_output_invalid") from error
    if not isinstance(payload, dict):
        raise AutomatedDogfoodFailure(stage, "json_object_required")
    return payload


def _validate_child_report(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("status") != "passed":
        raise AutomatedDogfoodFailure(kind, "child_status_not_passed")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise AutomatedDogfoodFailure(kind, "child_checks_missing")
    for name, value in checks.items():
        expected = False if name in {"raw_value_exposure"} else True
        if value is not expected:
            raise AutomatedDogfoodFailure(kind, "child_check_failed")
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise AutomatedDogfoodFailure(kind, "child_metrics_missing")
    if metrics.get("external_side_effect_count") != 0:
        raise AutomatedDogfoodFailure(kind, "external_side_effect_observed")
    summary: dict[str, Any] = {
        "check_count": len(checks),
        "external_side_effect_count": 0,
    }
    if kind == "plugin":
        if (
            metrics.get("public_side_effect_count") != 1
            or metrics.get("protected_side_effect_count") != 0
        ):
            raise AutomatedDogfoodFailure(
                kind,
                "file_payload_side_effect_contract_failed",
            )
        summary["public_side_effect_count"] = 1
        summary["protected_side_effect_count"] = 0
    plugin_version = payload.get("plugin_version")
    if kind == "lifecycle":
        candidate = payload.get("candidate")
        if isinstance(candidate, dict):
            plugin_version = candidate.get("plugin_version")
    if isinstance(plugin_version, str):
        summary["plugin_version"] = plugin_version
    return summary


def _read_revision() -> str:
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    revision = result.stdout.strip()
    if result.returncode != 0 or len(revision) != 40:
        raise AutomatedDogfoodFailure("revision", "source_revision_missing")
    return revision


if __name__ == "__main__":
    raise SystemExit(main())
