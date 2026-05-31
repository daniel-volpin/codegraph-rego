"""Validate the canonical thesis evidence manifest."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else ROOT / candidate


def close(actual: Any, expected: float, tol: float = 0.0005) -> bool:
    try:
        return math.isclose(float(actual), expected, abs_tol=tol)
    except (TypeError, ValueError):
        return False


def claim_by_id(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {claim["claim_id"]: claim for claim in manifest.get("claims", [])}


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def validate_manifest(path: Path) -> list[str]:
    manifest = read_json(path)
    claims = claim_by_id(manifest)
    errors: list[str] = []

    for claim in manifest.get("claims", []):
        for artifact in claim.get("canonical_artifacts", []):
            require(rel_path(artifact).exists(), errors, f"missing artifact for {claim['claim_id']}: {artifact}")
            require(
                "thesis_final_remediation_supported_calibrated_codex_20260428_122959" not in artifact,
                errors,
                f"canonical manifest points at absent 20260428 remediation path: {artifact}",
            )
        provenance = claim.get("provenance", {})
        if provenance.get("exists"):
            prov_path = provenance.get("path")
            require(bool(prov_path), errors, f"{claim['claim_id']} provenance.exists=true but path is empty")
            if prov_path:
                require(rel_path(prov_path).exists(), errors, f"missing provenance for {claim['claim_id']}: {prov_path}")

    detection = claims.get("detection_headline")
    require(detection is not None, errors, "missing detection_headline claim")
    if detection:
        metrics = detection.get("metrics", {})
        require(metrics.get("tp") == 222, errors, "detection tp must be 222")
        require(metrics.get("fp") == 11, errors, "detection fp must be 11")
        require(metrics.get("tn") == 210, errors, "detection tn must be 210")
        require(metrics.get("fn") == 11, errors, "detection fn must be 11")
        require(close(metrics.get("precision"), 0.9528), errors, "detection precision must be 0.9528")
        require(close(metrics.get("recall"), 0.9528), errors, "detection recall must be 0.9528")
        require(close(metrics.get("f1"), 0.9528), errors, "detection f1 must be 0.9528")
        require(
            metrics.get("semantics") == "union_any_rule_over_selected_testcase_union",
            errors,
            "detection row-sum discrepancy must be recorded as union-any-rule semantics",
        )
        require(
            metrics.get("category_row_sums") == {"tp": 222, "fp": 9, "tn": 212, "fn": 11},
            errors,
            "detection category row sums must record FP=9/TN=212 discrepancy",
        )

    explanation = claims.get("explanation_citation_attribution")
    require(explanation is not None, errors, "missing explanation_citation_attribution claim")
    if explanation:
        tp = explanation.get("metrics", {}).get("tp", {})
        fp = explanation.get("metrics", {}).get("fp", {})
        require(
            tp.get("count") == 222 and tp.get("with_context") == 222 and tp.get("without_context") == 0,
            errors,
            "explanation TP cohort must be 222/222 with context and 0/222 no-context",
        )
        require(
            fp.get("count") == 9 and fp.get("with_context") == 9 and fp.get("without_context") == 0,
            errors,
            "explanation FP cohort must be 9/9 with context and 0/9 no-context",
        )

    f10 = claims.get("f10_lexical_noise_java")
    require(f10 is not None, errors, "missing f10_lexical_noise_java claim")
    if f10:
        require(
            f10.get("metrics", {}).get("delta_fpr_ci") == [-0.5, -0.15384615384615385],
            errors,
            "F10 LexicalNoiseJava CI must use regenerated [-0.500, -0.154] values",
        )

    rem_v2 = claims.get("remediation_v2_historical_25_of_25")
    require(rem_v2 is not None, errors, "missing remediation_v2_historical_25_of_25 claim")
    if rem_v2:
        require(
            rem_v2.get("status") != "fully_provenance_backed",
            errors,
            "remediation v2 must not be marked fully provenance-backed",
        )
        require(
            not rem_v2.get("provenance", {}).get("exists"),
            errors,
            "remediation v2 provenance.exists must be false",
        )

    rem_pr = claims.get("remediation_pr_reproducibility_19_of_25")
    require(rem_pr is not None, errors, "missing remediation_pr_reproducibility_19_of_25 claim")
    if rem_pr:
        require(rem_pr.get("status") == "fully_provenance_backed", errors, "canonical remediation must be provenance-backed")
        metrics = rem_pr.get("metrics", {})
        require(metrics.get("attempted") == 25, errors, "canonical remediation attempted must be 25")
        require(metrics.get("fix_success") == 19, errors, "canonical remediation must not be labelled 25/25")
        require(rem_pr.get("provenance", {}).get("model") == "gpt-5.4-mini", errors, "canonical remediation model mismatch")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        default="outputs/thesis_canonical_2026-05-31/manifest.json",
        help="Path to canonical thesis manifest JSON.",
    )
    args = parser.parse_args()
    errors = validate_manifest(rel_path(args.manifest))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("canonical thesis artifact manifest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
