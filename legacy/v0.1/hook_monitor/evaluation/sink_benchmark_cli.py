from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hook_monitor.evaluation.cli_support import write_json_atomic
from hook_monitor.evaluation.sink_benchmark import (
    evaluate_sink_benchmark,
    render_sink_benchmark_report,
)
from hook_monitor.evaluation.sink_benchmark_dataset import (
    SinkBenchmarkDatasetError,
    load_sink_benchmark_dataset,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "sink_benchmark" / "v1_1"
)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_sink_benchmark_dataset(args.dataset)
        report = evaluate_sink_benchmark(
            dataset,
            split=None if args.split == "all" else args.split,
        )
        if args.output_json is not None:
            write_json_atomic(args.output_json, report)
    except (SinkBenchmarkDatasetError, OSError, ValueError) as error:
        print(f"sink benchmark error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_sink_benchmark_report(report))
    if args.check and not report["summary"]["quality_gate_passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare direct lexical, resolved lexical, optional semantic, and "
            "runtime-lineage profiles without executing target tools."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Versioned sink benchmark dataset directory.",
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
            "Return exit code 1 if privacy, runtime parity, or benchmark "
            "coverage invariants fail. Accuracy is reported but not gated yet."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
