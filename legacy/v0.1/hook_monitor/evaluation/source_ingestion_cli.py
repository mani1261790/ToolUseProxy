from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hook_monitor.evaluation.cli_support import write_json_atomic
from hook_monitor.evaluation.source_ingestion import (
    DEFAULT_FINDING_MIN_SCORE,
    DEFAULT_MINIMUM_PATH_SCORE,
    evaluate_source_ingestion,
    render_source_ingestion_report,
)
from hook_monitor.evaluation.source_ingestion_dataset import (
    SourceIngestionDatasetError,
    load_source_ingestion_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "similarity" / "ingestion" / "v3"
)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_source_ingestion_dataset(args.dataset)
        report = evaluate_source_ingestion(
            dataset,
            split=None if args.split == "all" else args.split,
            minimum_path_score=args.minimum_path_score,
            finding_min_score=args.finding_min_score,
        )
        if args.output_json is not None:
            write_json_atomic(args.output_json, report)
    except (SourceIngestionDatasetError, OSError, ValueError) as error:
        print(f"source-ingestion evaluation error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_source_ingestion_report(report))
    if args.check and not report["summary"]["quality_gate_passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure source-file chunking, raw Hook ingestion, adapter extraction, "
            "runtime lineage, and policy without executing target tools."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Versioned source-ingestion dataset directory.",
    )
    parser.add_argument(
        "--split",
        choices=("development", "validation", "all"),
        default="development",
        help="Dataset split. Defaults to development; validation is for comparison.",
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
        "--minimum-path-score",
        type=float,
        default=DEFAULT_MINIMUM_PATH_SCORE,
        help="Lineage propagation floor.",
    )
    parser.add_argument(
        "--finding-min-score",
        type=float,
        default=DEFAULT_FINDING_MIN_SCORE,
        help="Leak finding score floor.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Return exit code 1 if parity fails, or if a scored v3 quality "
            "metric regresses."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
