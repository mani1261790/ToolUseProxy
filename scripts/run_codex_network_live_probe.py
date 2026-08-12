from __future__ import annotations

import argparse
import json
import sys

from hook_monitor.evaluation.codex_network_live import (
    CodexNetworkLiveError,
    render_codex_network_live_report,
    run_codex_network_live_probe,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure Codex app-server approvals and OTel network-policy events with "
            "a loopback-only synthetic model; decline any approval."
        )
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Required acknowledgement that fixed synthetic network attempts will run.",
    )
    parser.add_argument("--codex-bin", default="codex", help="Codex executable.")
    parser.add_argument("--repeats", type=int, default=3, help="Probe repetitions (1-20).")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="Stdout format."
    )
    parser.add_argument(
        "--require-live-contract",
        action="store_true",
        help="Return exit code 1 unless every OTel policy event is observed safely.",
    )
    args = parser.parse_args(argv)
    if not args.execute:
        print("Codex network live probe error: --execute is required", file=sys.stderr)
        return 2
    try:
        report = run_codex_network_live_probe(
            args.codex_bin,
            repeats=args.repeats,
        )
    except (CodexNetworkLiveError, OSError, ValueError) as error:
        print(f"Codex network live probe error: {error}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_codex_network_live_report(report))
    if args.require_live_contract and not report["summary"]["live_contract_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
