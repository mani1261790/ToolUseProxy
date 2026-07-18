from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from hook_monitor.evaluation.dataset import (
    SimilarityDatasetError,
    load_similarity_dataset,
)
from hook_monitor.evaluation.similarity import (
    DEFAULT_FINDING_MIN_SCORE,
    DEFAULT_MINIMUM_PATH_SCORE,
    evaluate_similarity,
    render_similarity_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT = REPO_ROOT / "tests" / "fixtures" / "similarity" / "v1"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_similarity_dataset(args.dataset)
        report = evaluate_similarity(
            dataset,
            split=None if args.split == "all" else args.split,
            benchmark_repeats=args.benchmark_repeats,
            minimum_path_score=args.minimum_path_score,
            finding_min_score=args.finding_min_score,
        )
        if args.output_json is not None:
            _write_json_atomic(args.output_json, report)
    except (SimilarityDatasetError, OSError, ValueError) as error:
        print(f"similarity evaluation error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_similarity_report(report))
    if args.check and not report["summary"]["parity_passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure the current local similarity, lineage, and policy baseline "
            "without changing Hook runtime behavior."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_ROOT,
        help="Versioned similarity dataset directory.",
    )
    parser.add_argument(
        "--split",
        choices=("development", "validation", "all"),
        default="development",
        help="Dataset split. Defaults to development; validation is reserved for comparison.",
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
        "--benchmark-repeats",
        type=int,
        default=20,
        help="Number of local latency samples per case.",
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
        help="Return exit code 1 if full/incremental graph parity fails.",
    )
    return parser.parse_args(argv)


def _write_json_atomic(path: Path, report: dict[str, object]) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise OSError(f"output directory does not exist: {parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
