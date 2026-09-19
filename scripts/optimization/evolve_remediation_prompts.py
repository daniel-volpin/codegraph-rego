"""
CLI for self-improving prompt and tool evolution using TextGrad and DSPy optimizers.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.optimization import (  # noqa: E402
    DSPyPromptCompiler,
    TextGradPromptOptimizer,
    bootstrap_few_shot_demos_from_results,
)
from codegraph.remediation.agentic.prompts import SYSTEM_PROMPT_TEMPLATE  # noqa: E402
from codegraph.telemetry import configure_telemetry, get_tracer  # noqa: E402

LOGGER = logging.getLogger("codegraph.optimization.cli")
_tracer = get_tracer("codegraph.optimization.evolution")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evolve and optimize remediation agent system prompts using TextGrad textual gradients.",
    )
    parser.add_argument(
        "--results-file",
        required=True,
        help="Path to an evaluation results.jsonl (e.g. outputs/golden_20_local_lmstudio/results.jsonl).",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/prompt_optimization/latest",
        help="Directory to write prompt evolution checkpoints and telemetry.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model override for the TextGrad optimizer critic.",
    )
    parser.add_argument(
        "--enable-few-shot-bootstrap",
        action="store_true",
        help="Bootstrap DSPy verified few-shot trajectories into the evolved prompt.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_telemetry()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    results_path = Path(args.results_file).resolve()
    if not results_path.is_file():
        LOGGER.error("Results file not found at %s", results_path)
        return 1

    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    LOGGER.info("Loaded %d remediation results from %s", len(records), results_path)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    optimizer = TextGradPromptOptimizer()
    with _tracer.start_as_current_span("prompt.evolution") as span:
        span.set_attribute("optimization.results_count", len(records))

        updated_prompt, gradients, rationale = optimizer.optimize_prompt(
            SYSTEM_PROMPT_TEMPLATE,
            records,  # type: ignore[arg-type]
            model=args.model,
        )

        if args.enable_few_shot_bootstrap:
            demos = bootstrap_few_shot_demos_from_results(records)
            compiler = DSPyPromptCompiler(demonstrations=demos)
            updated_prompt = compiler.compile_instruction_prompt(updated_prompt)
            LOGGER.info("Bootstrapped %d verified few-shot demonstrations into prompt.", len(demos))

        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "results_source": str(results_path),
            "total_evaluated_cases": len(records),
            "accumulated_gradients_count": len(gradients),
            "gradients": gradients,
            "rationale": rationale,
            "optimized_prompt": updated_prompt,
        }

        report_file = out_dir / "prompt_evolution_report.json"
        prompt_file = out_dir / "SYSTEM_PROMPT_OPTIMIZED.md"

        report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        prompt_file.write_text(updated_prompt, encoding="utf-8")

        LOGGER.info("Saved prompt evolution report to %s", report_file)
        LOGGER.info("Saved optimized prompt to %s", prompt_file)
        span.set_attribute("optimization.gradients_count", len(gradients))

    return 0


if __name__ == "__main__":
    sys.exit(main())
