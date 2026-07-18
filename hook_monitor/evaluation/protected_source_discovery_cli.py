from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hook_monitor.evaluation.cli_support import write_json_atomic
from hook_monitor.evaluation.protected_source_discovery import (
    ProtectedSourceDiscoveryDatasetError,
    evaluate_protected_source_discovery,
    load_protected_source_discovery_dataset,
    render_protected_source_discovery_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "protected_source_discovery" / "v2"
)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_protected_source_discovery_dataset(args.dataset)
        report = evaluate_protected_source_discovery(
            dataset,
            split=None if args.split == "all" else args.split,
        )
        if args.output_json is not None:
            write_json_atomic(args.output_json, report)
    except (ProtectedSourceDiscoveryDatasetError, OSError, ValueError) as error:
        print(f"protected-source discovery evaluation error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_protected_source_discovery_report(report))
    if args.check and not report["summary"]["check_passed"]:
        return 1
    if args.require_go and not report["summary"]["go_no_go_passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate bounded local protected-source discovery against the "
            "versioned synthetic workspace corpus."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Versioned protected-source discovery dataset directory.",
    )
    parser.add_argument(
        "--split",
        choices=("development", "validation", "all"),
        default="all",
        help="Dataset split. Defaults to the complete versioned corpus.",
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
        help="Atomically write the deterministic machine-readable report.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Check the pinned corpus digest, explicit detector baseline, privacy, "
            "and scanner invariants. Numeric go/no-go targets remain reported but "
            "do not control this reproducibility check."
        ),
    )
    parser.add_argument(
        "--require-go",
        action="store_true",
        help="Exit with status 1 when the selected split misses a numeric GO gate.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
