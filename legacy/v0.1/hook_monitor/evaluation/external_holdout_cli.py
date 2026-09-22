from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hook_monitor.evaluation.cli_support import write_json_atomic
from hook_monitor.evaluation.external_holdout import (
    ExternalHoldoutError,
    evaluate_external_holdout,
    load_external_holdout,
    render_external_holdout_report,
)
from hook_monitor.evaluation.similarity import (
    DEFAULT_FINDING_MIN_SCORE,
    DEFAULT_MINIMUM_PATH_SCORE,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        dataset = load_external_holdout(
            args.dataset,
            forbidden_repository_root=REPO_ROOT,
        )
        report = evaluate_external_holdout(
            dataset,
            benchmark_repeats=args.benchmark_repeats,
            minimum_path_score=args.minimum_path_score,
            finding_min_score=args.finding_min_score,
        )
        if args.output_json is not None:
            write_json_atomic(args.output_json, report)
    except (ExternalHoldoutError, OSError) as error:
        code = error.code if isinstance(error, ExternalHoldoutError) else "output_failed"
        record = (
            f" record={error.record_number}"
            if isinstance(error, ExternalHoldoutError)
            and error.record_number is not None
            else ""
        )
        print(f"external holdout error: {code}{record}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_external_holdout_report(report))
    if args.require_go and not report["quality"]["passed"]:
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate a repository-external private similarity holdout and emit "
            "only an aggregate public report."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Private holdout directory outside the ToolUseProxy repository.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Aggregate-only stdout format.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Atomically write the aggregate-only public report.",
    )
    parser.add_argument(
        "--benchmark-repeats",
        type=int,
        default=1,
        help="Local latency samples per private case.",
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
        "--require-go",
        action="store_true",
        help="Return exit code 1 unless every fixed external holdout gate passes.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
