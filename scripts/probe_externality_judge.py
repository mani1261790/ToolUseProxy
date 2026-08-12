#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_monitor.externality.providers import (  # noqa: E402
    CodexExecJudge,
    build_codex_probe_receipt,
    resolve_codex_executable_identity,
    write_codex_probe_receipt,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the value-free Codex externality-judge capability probe."
    )
    parser.add_argument("--codex", default="codex", help="Codex executable")
    parser.add_argument("--model", help="Optional Codex model override")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument(
        "--write-receipt",
        type=Path,
        help="Write a mode-0600 capability receipt after a passing probe.",
    )
    args = parser.parse_args(argv)

    identity = resolve_codex_executable_identity(args.codex)
    probe = CodexExecJudge(
        executable=identity.executable_path,
        model=args.model,
        timeout_seconds=args.timeout_seconds,
    ).probe()
    if probe.eligible and args.write_receipt is not None:
        identity_after_probe = resolve_codex_executable_identity(
            identity.executable_path
        )
        if identity_after_probe != identity:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "eligible": False,
                        "reason_codes": ["codex_identity_changed"],
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                )
            )
            return 1
        receipt = build_codex_probe_receipt(
            probe,
            identity=identity,
            model=args.model,
        )
        write_codex_probe_receipt(args.write_receipt, receipt)
    output = {
        "schema_version": 1,
        "eligible": probe.eligible,
        "reason_codes": list(probe.reason_codes),
        "provider": (
            probe.local_observation.provider
            if probe.local_observation is not None
            else "codex_exec"
        ),
        "model": (
            probe.local_observation.model
            if probe.local_observation is not None
            else args.model or "codex_default"
        ),
        "local_verdict": (
            probe.local_observation.verdict.verdict
            if probe.local_observation is not None
            else "unavailable"
        ),
        "risky_verdict": (
            probe.risky_observation.verdict.verdict
            if probe.risky_observation is not None
            else "unavailable"
        ),
        "local_latency_ms": (
            probe.local_observation.latency_ms
            if probe.local_observation is not None
            else None
        ),
        "risky_latency_ms": (
            probe.risky_observation.latency_ms
            if probe.risky_observation is not None
            else None
        ),
    }
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0 if probe.eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
