"""
Run a deterministic experiment sequence (detection + explanation + remediation) and emit a manifest.

This is meant to support thesis reproducibility: a single command ties metrics outputs to a git SHA and config.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codegraph.benchmark_registry import supported_remediation_rule_ids
from codegraph.evaluation.benchmark import load_mapping_config

LOGGER = logging.getLogger("codegraph.eval.experiments")


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _run(cmd: list[str]) -> None:
    LOGGER.info("Running: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)


def _git_sha(repo_root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root).decode("utf-8").strip()


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _supported_remediation_rule_ids() -> list[str]:
    return sorted(supported_remediation_rule_ids())


def _partition_categories_for_remediation(
    selection_cfg: dict[str, Any],
    mapping_path: Path,
) -> tuple[list[str], list[dict[str, str]]]:
    selected_category_ids = selection_cfg.get("categories") or []
    by_id = {spec.id: spec for spec in load_mapping_config(mapping_path)}

    attempted: list[str] = []
    skipped: list[dict[str, str]] = []
    for category_id in selected_category_ids:
        spec = by_id.get(str(category_id))
        if spec and spec.remediation_tier in {"full", "guarded"}:
            attempted.append(str(category_id))
        else:
            skipped.append(
                {
                    "category_id": str(category_id),
                    "reason": "no_supported_remediation_rules",
                }
            )
    return attempted, skipped


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run detection + explanation + remediation experiments.")
    parser.add_argument(
        "--config",
        default="configs/benchmark/multicat_medium.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--mapping",
        default="configs/benchmark/policy_registry.json",
        help="Control/CWE/Rego mapping JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output-root",
        default="outputs",
        help="Output root directory (default: %(default)s). Experiment outputs are created under this root.",
    )
    parser.add_argument(
        "--experiment-name",
        default=None,
        help="Optional experiment folder name (default: experiment_<config>_<utc>).",
    )
    parser.add_argument(
        "--reset-neo4j",
        action="store_true",
        help="Clear Neo4j before each stage (recommended for deterministic runs).",
    )
    parser.add_argument(
        "--remediation-sample-size",
        type=int,
        default=10,
        help="Number of remediation attempts (default: %(default)s).",
    )
    parser.add_argument(
        "--remediation-max-attempts",
        type=int,
        default=2,
        help="Max attempts per violation during remediation (default: %(default)s).",
    )
    parser.add_argument(
        "--remediation-mode",
        choices=["dry_run", "apply"],
        default="dry_run",
        help="Remediation mode (default: %(default)s).",
    )
    parser.add_argument(
        "--remediation-seed",
        type=int,
        default=11,
        help="Seed for remediation sampling (default: %(default)s).",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    selection_path = (repo_root / args.config).resolve() if not os.path.isabs(args.config) else Path(args.config)
    mapping_path = (repo_root / args.mapping).resolve() if not os.path.isabs(args.mapping) else Path(args.mapping)

    output_root = (
        (repo_root / args.output_root).resolve() if not os.path.isabs(args.output_root) else Path(args.output_root)
    )
    output_root.mkdir(parents=True, exist_ok=True)

    config_stem = selection_path.stem.replace(".", "_")
    experiment_name = args.experiment_name or f"experiment_{config_stem}_{_utc_stamp()}"
    exp_dir = output_root / experiment_name
    exp_dir.mkdir(parents=True, exist_ok=True)

    stage_dirs = {
        "benchmark": exp_dir / "benchmark_eval",
        "explanation": exp_dir / "explanation_eval",
        "remediation": exp_dir / "remediation_eval",
    }
    for path in stage_dirs.values():
        path.mkdir(parents=True, exist_ok=True)

    selection_cfg = _load_json(selection_path)
    commands_executed: list[str] = []

    def add_and_run(cmd: list[str]) -> None:
        commands_executed.append(" ".join(cmd))
        _run(cmd)

    # Stage A: detection metrics.
    cmd = [
        sys.executable,
        str(repo_root / "run_benchmark_eval.py"),
        "--config",
        str(selection_path),
        "--mapping",
        str(mapping_path),
        "--output-dir",
        str(stage_dirs["benchmark"]),
        "--workdir",
        str(exp_dir / "workdir_benchmark"),
    ]
    if args.reset_neo4j:
        cmd.append("--reset-neo4j")
    add_and_run(cmd)

    # Stage B: explanation metrics.
    cmd = [
        sys.executable,
        str(repo_root / "run_explanation_eval.py"),
        "--config",
        str(selection_path),
        "--mapping",
        str(mapping_path),
        "--output-dir",
        str(stage_dirs["explanation"]),
        "--workdir",
        str(exp_dir / "workdir_explanation"),
    ]
    if args.reset_neo4j:
        cmd.append("--reset-neo4j")
    add_and_run(cmd)

    # Stage C: remediation metrics (only for categories with supported remediation strategies).
    remediation_attempted, remediation_skipped = _partition_categories_for_remediation(selection_cfg, mapping_path)
    remediation_config_path: Path | None = None
    if remediation_attempted:
        remediation_config_path = exp_dir / "selection_for_remediation.json"
        remediation_cfg = dict(selection_cfg)
        remediation_cfg["categories"] = remediation_attempted
        with remediation_config_path.open("w", encoding="utf-8") as handle:
            json.dump(remediation_cfg, handle, indent=2, ensure_ascii=True, sort_keys=False)
            handle.write("\n")

        cmd = [
            sys.executable,
            str(repo_root / "run_remediation_eval.py"),
            "--config",
            str(remediation_config_path),
            "--mapping",
            str(mapping_path),
            "--output-dir",
            str(stage_dirs["remediation"]),
            "--workdir",
            str(exp_dir / "workdir_remediation"),
            "--sample-size",
            str(args.remediation_sample_size),
            "--max-attempts",
            str(args.remediation_max_attempts),
            "--mode",
            str(args.remediation_mode),
            "--seed",
            str(args.remediation_seed),
        ]
        if args.reset_neo4j:
            cmd.append("--reset-neo4j")
        add_and_run(cmd)
    else:
        LOGGER.warning("Skipping remediation stage: no categories with supported remediation strategies.")

    manifest = {
        "git_sha": _git_sha(repo_root),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "config_path": str(selection_path),
        "mapping_path": str(mapping_path),
        "owasp_root": os.environ.get("OWASP_BENCHMARK_ROOT"),
        "commands_executed": commands_executed,
        "output_dirs": {key: str(value) for key, value in stage_dirs.items()},
        "remediation": {
            "supported_rule_ids": _supported_remediation_rule_ids(),
            "categories_attempted": remediation_attempted,
            "categories_skipped": remediation_skipped,
            "selection_config_used": str(remediation_config_path) if remediation_config_path else None,
        },
    }
    manifest_path = exp_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=True, sort_keys=False)
        handle.write("\n")

    LOGGER.info("Experiment complete. Manifest written to %s", manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
