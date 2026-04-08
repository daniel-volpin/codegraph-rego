from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_MODELS = ["qwen/qwen3-coder-30b", "qwen3.5-27b"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a remediation model bake-off over the bounded benchmark subset.")
    parser.add_argument(
        "--models",
        nargs="+",
        default=DEFAULT_MODELS,
        help="Remediation model ids to evaluate (default: %(default)s)",
    )
    parser.add_argument(
        "--config",
        default="configs/benchmark/remediation_bounded_smoke.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--mapping",
        default="configs/benchmark/policy_registry.json",
        help="Control/CWE/Rego mapping JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/remediation_model_bakeoff",
        help="Output directory for bake-off summaries (default: %(default)s)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=3,
        help="Number of benchmark violations to attempt per model (default: %(default)s)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=2,
        help="Maximum remediation attempts per violation (default: %(default)s)",
    )
    parser.add_argument(
        "--mode",
        choices=["dry_run", "apply"],
        default="dry_run",
        help="Remediation execution mode (default: %(default)s)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Remediation-specific LLM temperature override (default: %(default)s)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=2048,
        help="Remediation-specific LLM max token override (default: %(default)s)",
    )
    parser.add_argument(
        "--reset-neo4j",
        action="store_true",
        help="Reset Neo4j before each remediation evaluation run.",
    )
    parser.add_argument(
        "--python",
        default=".venv/bin/python3",
        help="Python executable to use for nested remediation runs (default: %(default)s)",
    )
    parser.add_argument(
        "--load-with-lms",
        action="store_true",
        help="Load each LM Studio model explicitly via `lms load -y` before running it.",
    )
    return parser.parse_args()


def _slugify_model(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", model)


def _status_counts(results: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _summarize_metrics(model: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
    results = list(metrics.get("results") or [])
    status_counts = _status_counts(results)
    generation_valid = sum(
        1
        for item in results
        if isinstance(item.get("generation"), dict) and item["generation"].get("raw_response_valid") is True
    )
    replace_method_valid = sum(
        1
        for item in results
        if isinstance(item.get("generation"), dict)
        and item["generation"].get("raw_response_valid") is True
        and item["generation"].get("decision") == "replace_method"
    )
    no_fix_count = sum(
        1
        for item in results
        if isinstance(item.get("generation"), dict) and item["generation"].get("decision") == "no_fix"
    )
    patch_applied = sum(1 for item in results if item.get("patch_applied"))
    policy_pass = sum(1 for item in results if item.get("policy_pass") is True)
    build_attempted = sum(1 for item in results if item.get("build_pass") is not None)
    build_success = sum(1 for item in results if item.get("build_pass") is True)

    return {
        "model": model,
        "attempted": metrics.get("attempted"),
        "fix_success": metrics.get("fix_success"),
        "fix_success_rate": metrics.get("fix_success_rate"),
        "build_attempted": metrics.get("build_attempted"),
        "build_success": metrics.get("build_success"),
        "build_success_rate": metrics.get("build_success_rate"),
        "generation_valid": generation_valid,
        "replace_method_valid": replace_method_valid,
        "patch_applied": patch_applied,
        "policy_pass": policy_pass,
        "build_attempted_from_results": build_attempted,
        "build_success_from_results": build_success,
        "no_fix_count": no_fix_count,
        "status_counts": status_counts,
    }


def _render_markdown(summary_rows: List[Dict[str, Any]]) -> str:
    headers = [
        "Model",
        "Attempted",
        "Structured Valid",
        "Replace Valid",
        "Patch Applied",
        "Build Attempts",
        "Build Success",
        "Policy Pass",
        "NO_FIX",
        "Top Statuses",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in summary_rows:
        top_statuses = ", ".join(f"{k}:{v}" for k, v in sorted(row["status_counts"].items()))
        lines.append(
            "| "
            + " | ".join(
                [
                    row["model"],
                    str(row["attempted"]),
                    str(row["generation_valid"]),
                    str(row["replace_method_valid"]),
                    str(row["patch_applied"]),
                    str(row["build_attempted"]),
                    str(row["build_success"]),
                    str(row["policy_pass"]),
                    str(row["no_fix_count"]),
                    top_statuses or "-",
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _run_lms_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [os.path.expanduser("~/.lmstudio/bin/lms"), *args],
        check=False,
        text=True,
        capture_output=True,
    )


def _normalize_loaded_model_name(name: str) -> str:
    return re.sub(r"\s+\(\d+\s+variant[s]?\)$", "", name.strip())


def _loaded_models() -> List[str]:
    result = _run_lms_command("ls")
    loaded: List[str] = []
    for line in result.stdout.splitlines():
        if "✓ LOADED" not in line:
            continue
        name = re.split(r"\s{2,}", line.strip(), maxsplit=1)[0]
        loaded.append(_normalize_loaded_model_name(name))
    return loaded


def _terminate_process(process: subprocess.Popen[str], timeout_seconds: float = 3.0) -> Dict[str, Any]:
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return {"stdout": stdout, "stderr": stderr, "timed_out": False}
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {"stdout": stdout, "stderr": stderr, "timed_out": True}


def _wait_for_loaded_models(
    expected_loaded: List[str], timeout_seconds: float = 90.0, poll_seconds: float = 1.5
) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    normalized_expected = sorted(_normalize_loaded_model_name(model) for model in expected_loaded)
    observations: List[List[str]] = []
    while time.time() < deadline:
        current = sorted(_loaded_models())
        observations.append(current)
        if current == normalized_expected:
            return {"ok": True, "loaded_models": current, "observations": observations}
        time.sleep(poll_seconds)
    return {"ok": False, "loaded_models": sorted(_loaded_models()), "observations": observations}


def _unload_all_models() -> Dict[str, Any]:
    process = subprocess.Popen(
        [os.path.expanduser("~/.lmstudio/bin/lms"), "unload", "--all"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_result = _wait_for_loaded_models([])
    process_result = _terminate_process(process)
    return {
        "wait_ok": wait_result["ok"],
        "loaded_models": wait_result["loaded_models"],
        "observations": wait_result["observations"],
        "stdout": process_result["stdout"],
        "stderr": process_result["stderr"],
        "timed_out": process_result["timed_out"],
    }


def _load_single_model(model: str) -> Dict[str, Any]:
    unload_result = _unload_all_models()
    process = subprocess.Popen(
        [os.path.expanduser("~/.lmstudio/bin/lms"), "load", "-y", model],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_result = _wait_for_loaded_models([model])
    process_result = _terminate_process(process, timeout_seconds=5.0)
    return {
        "unload_wait_ok": unload_result["wait_ok"],
        "unload_loaded_models": unload_result["loaded_models"],
        "unload_observations": unload_result["observations"],
        "unload_stdout": unload_result["stdout"],
        "unload_stderr": unload_result["stderr"],
        "unload_timed_out": unload_result["timed_out"],
        "load_wait_ok": wait_result["ok"],
        "load_loaded_models": wait_result["loaded_models"],
        "load_observations": wait_result["observations"],
        "load_stdout": process_result["stdout"],
        "load_stderr": process_result["stderr"],
        "load_timed_out": process_result["timed_out"],
    }


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_rows: List[Dict[str, Any]] = []

    for model in args.models:
        slug = _slugify_model(model)
        model_output_dir = output_dir / slug
        model_output_dir.mkdir(parents=True, exist_ok=True)

        load_metadata: Dict[str, Any] | None = None
        if args.load_with_lms:
            load_metadata = _load_single_model(model)
            (model_output_dir / "load.log").write_text(
                "\n".join(
                    [
                        "[unload stdout]",
                        load_metadata.get("unload_stdout") or "",
                        "[unload stderr]",
                        load_metadata.get("unload_stderr") or "",
                        "[load stdout]",
                        load_metadata.get("load_stdout") or "",
                        "[load stderr]",
                        load_metadata.get("load_stderr") or "",
                        "[loaded models after load]",
                        ", ".join(load_metadata.get("load_loaded_models") or []),
                    ]
                ),
                encoding="utf-8",
            )
            if not load_metadata.get("load_wait_ok"):
                summary_rows.append(
                    {
                        "model": model,
                        "attempted": 0,
                        "fix_success": 0,
                        "fix_success_rate": 0.0,
                        "build_attempted": 0,
                        "build_success": 0,
                        "build_success_rate": 0.0,
                        "generation_valid": 0,
                        "replace_method_valid": 0,
                        "patch_applied": 0,
                        "policy_pass": 0,
                        "build_attempted_from_results": 0,
                        "build_success_from_results": 0,
                        "no_fix_count": 0,
                        "status_counts": {"MODEL_LOAD_FAILED": 1},
                        "returncode": 1,
                    }
                )
                continue

        env = os.environ.copy()
        env["REMEDIATION_LLM_MODEL"] = model
        env["REMEDIATION_LLM_MAX_TOKENS"] = str(args.max_tokens)
        env["REMEDIATION_LLM_TEMPERATURE"] = str(args.temperature)

        cmd = [
            args.python,
            "run_remediation_eval.py",
            "--config",
            args.config,
            "--mapping",
            args.mapping,
            "--output-dir",
            model_output_dir.as_posix(),
            "--sample-size",
            str(args.sample_size),
            "--max-attempts",
            str(args.max_attempts),
            "--mode",
            args.mode,
        ]
        if args.reset_neo4j:
            cmd.append("--reset-neo4j")

        run = subprocess.run(
            cmd,
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
        )
        (model_output_dir / "run.log").write_text(
            run.stdout + ("\n" + run.stderr if run.stderr else ""), encoding="utf-8"
        )

        metrics_path = model_output_dir / "remediation_metrics.json"
        if not metrics_path.exists():
            summary_rows.append(
                {
                    "model": model,
                    "attempted": 0,
                    "fix_success": 0,
                    "fix_success_rate": 0.0,
                    "build_attempted": 0,
                    "build_success": 0,
                    "build_success_rate": 0.0,
                    "generation_valid": 0,
                    "replace_method_valid": 0,
                    "patch_applied": 0,
                    "policy_pass": 0,
                    "build_attempted_from_results": 0,
                    "build_success_from_results": 0,
                    "no_fix_count": 0,
                    "status_counts": {"RUN_FAILED": 1},
                    "returncode": run.returncode,
                }
            )
            if args.load_with_lms:
                _unload_all_models()
            continue

        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        summary = _summarize_metrics(model, metrics)
        summary["returncode"] = run.returncode
        summary_rows.append(summary)
        if args.load_with_lms:
            _unload_all_models()

    overall = {
        "models": summary_rows,
    }
    (output_dir / "summary.json").write_text(json.dumps(overall, indent=2), encoding="utf-8")
    (output_dir / "summary.md").write_text(_render_markdown(summary_rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
