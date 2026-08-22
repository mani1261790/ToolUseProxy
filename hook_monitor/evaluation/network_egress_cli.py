from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hook_monitor.evaluation.cli_support import write_json_atomic
from hook_monitor.evaluation.network_egress import (
    NetworkEgressDatasetError,
    evaluate_network_egress,
    load_network_egress_dataset,
    render_network_egress_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "network_egress" / "v1"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_network_egress_dataset(args.dataset)
        report = evaluate_network_egress(
            dataset,
            split=None if args.split == "all" else args.split,
        )
        if args.output_json is not None:
            write_json_atomic(args.output_json, report)
    except (NetworkEgressDatasetError, OSError, ValueError) as error:
        print(f"network egress error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_network_egress_report(report))
    if args.check and not report["summary"]["foundation_gate_passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare value-free adapter classifications with recorded network "
            "observations without executing network calls."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Versioned network-egress dataset directory.",
    )
    parser.add_argument(
        "--split",
        choices=("development", "validation", "all"),
        default="development",
        help="Dataset split. Validation remains a held-out comparison split.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Stdout format.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Atomically write the complete machine-readable report.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Return exit code 1 if privacy or dataset coverage invariants fail. "
            "Baseline accuracy is reported but not gated."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
