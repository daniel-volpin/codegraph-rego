#!/usr/bin/env python3
"""Merge per-policy-group detection runs into one result set.

A full-corpus run ingests every category into one graph, so a failure anywhere
discards the whole run. Evaluating one group at a time keeps each ingestion
small and independently repeatable; this script reassembles the groups.

The Overall row is recomputed from per-case fired rules under the same union
any-rule definition the single-run path uses. It is never summed from the
per-category rows, because a case selected under one category can fire an
off-target rule from another and would otherwise be counted twice or lost.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.benchmark import CategorySpec, load_mapping_config  # noqa: E402
from codegraph.evaluation.io import render_markdown_table, write_csv, write_json  # noqa: E402

LOGGER = logging.getLogger("compose_benchmark_eval")

CASE_OUTCOMES_FILENAME = "case_outcomes.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group_dirs", nargs="+", help="Group output directories to merge")
    parser.add_argument("--mapping", default="configs/benchmark/policy_registry.json")
    parser.add_argument("--output-dir", required=True, help="Directory for the merged result set")
    return parser.parse_args()


def _load_case_outcomes(group_dirs: list[Path]) -> dict[str, dict[str, Any]]:
    """Per-case outcomes keyed by testcase, refusing contradictory duplicates."""
    outcomes: dict[str, dict[str, Any]] = {}
    for group_dir in group_dirs:
        path = group_dir / CASE_OUTCOMES_FILENAME
        if not path.is_file():
            raise SystemExit(
                f"{path} is missing. Re-run that group with the current "
                "run_benchmark_eval.py, which writes per-case outcomes."
            )
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            testcase_id = record["testcase_id"]
            existing = outcomes.get(testcase_id)
            if existing and existing["violation_ids"] != record["violation_ids"]:
                raise SystemExit(
                    f"{testcase_id} has different findings in two groups "
                    f"({existing['category_id']} vs {record['category_id']}); "
                    "the groups were produced by different code or configuration."
                )
            outcomes[testcase_id] = record
    return outcomes


def _score(spec: CategorySpec, records: list[dict[str, Any]]) -> dict[str, Any]:
    rules = set(spec.rego_rules)
    tp = fp = tn = fn = 0
    for record in records:
        predicted = bool(rules.intersection(record["violation_ids"]))
        label = bool(record["label"])
        if label and predicted:
            tp += 1
        elif label:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "label": spec.label,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args()

    group_dirs = [Path(directory) for directory in args.group_dirs]
    missing = [str(directory) for directory in group_dirs if not directory.is_dir()]
    if missing:
        raise SystemExit(f"Missing group directories: {', '.join(missing)}")

    categories = load_mapping_config(Path(args.mapping))
    categories_by_id = {spec.id: spec for spec in categories}
    outcomes = _load_case_outcomes(group_dirs)

    by_category: dict[str, list[dict[str, Any]]] = {}
    for record in outcomes.values():
        by_category.setdefault(record["category_id"], []).append(record)

    metrics: dict[str, Any] = {}
    rows: list[list[Any]] = []
    for category_id, records in sorted(by_category.items()):
        spec = categories_by_id.get(category_id)
        if spec is None:
            LOGGER.warning("Skipping unknown category %s", category_id)
            continue
        stats = _score(spec, records)
        metrics[category_id] = stats
        rows.append(
            [
                stats["label"],
                stats["true_positives"],
                stats["false_positives"],
                stats["false_negatives"],
                stats["precision"],
                stats["recall"],
                stats["f1"],
            ]
        )

    all_rules = sorted({rule for spec in categories for rule in spec.rego_rules})
    overall_spec = CategorySpec(id="overall", label="Overall", cwes=[], rego_rules=all_rules)
    overall = _score(overall_spec, list(outcomes.values()))
    metrics["overall"] = overall
    rows.append(
        [
            "Overall",
            overall["true_positives"],
            overall["false_positives"],
            overall["false_negatives"],
            overall["precision"],
            overall["recall"],
            overall["f1"],
        ]
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        output_dir / "metrics.json",
        {
            "composed_from": [str(directory) for directory in group_dirs],
            "total_cases": len(outcomes),
            "metrics": metrics,
        },
    )
    headers = ["Category", "TP", "FP", "FN", "Precision", "Recall", "F1"]
    fieldnames = ["category", "tp", "fp", "fn", "precision", "recall", "f1"]
    write_csv(
        output_dir / "metrics.csv",
        [dict(zip(fieldnames, row, strict=True)) for row in rows],
        fieldnames,
    )
    (output_dir / "table.md").write_text(render_markdown_table(headers, rows), encoding="utf-8")

    LOGGER.info(
        "Composed %d cases from %d groups -> %s (overall F1 %.4f)",
        len(outcomes),
        len(group_dirs),
        output_dir,
        overall["f1"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
