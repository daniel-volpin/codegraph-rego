from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import pytest

from codegraph.policy import integration
from codegraph.policy.runtime import catalog as runtime_catalog
from codegraph.policy.runtime import opa as runtime_opa
from tests.codegraph.policy._test_helpers import BundleBuilder

Bundle = dict[str, Any]
RawViolation = dict[str, Any]
EvaluateBundle = Callable[[Bundle], list[RawViolation]]


@pytest.fixture(autouse=True)
def policy_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integration.shutil, "which", lambda _name: "/usr/local/bin/opa")
    monkeypatch.setattr(integration, "load_policy_catalog", lambda: {})
    monkeypatch.setattr(integration, "load_iso_rules", lambda: {})
    monkeypatch.setattr(integration, "get_policy_catalog_entries", lambda: [])
    monkeypatch.setattr(runtime_catalog, "resolve_catalog_entry", lambda _violation_id, _catalog: None)


def bundle(target_method: str, *, file_path: str | None = None, source_code: str = "") -> Bundle:
    return (
        BundleBuilder()
        .with_target_method(target_method)
        .with_file_path(file_path or target_method)
        .with_source_code(source_code)
        .with_vector_context([])
        .build()
    )


def violation(violation_id: str, *, reason: str = "r") -> RawViolation:
    return {"violation_id": violation_id, "reason": reason, "severity": "high"}


def install_policy_input(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bundles: list[Bundle],
    evaluator: EvaluateBundle,
) -> None:
    monkeypatch.setattr(integration, "build_policy_input", lambda **_kwargs: {"bundles": bundles})
    monkeypatch.setattr(runtime_opa, "evaluate_bundle", evaluator)


def violations_by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["violation_id"]): item for item in result["violations"]}


def count_violation_ids(violations: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in violations:
        key = str(item.get("violation_id"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def test_default_behavior_has_no_limit_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    bundles = [bundle("m1", file_path="f1"), bundle("m2", file_path="f2")]
    install_policy_input(monkeypatch, bundles=bundles, evaluator=lambda _bundle: [violation("A")])

    result = integration.evaluate_policies()

    assert "violations" in result
    assert "limits" not in result
    assert "truncated" not in result
    assert "violation_counts_by_id" not in result
    assert len(result["violations"]) == 2


def test_caps_total_and_per_violation_id_are_applied_after_concurrent_eval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundles = [bundle(f"m{idx}", file_path=f"f{idx}") for idx in range(1, 5)]
    calls: list[str] = []

    def evaluate(current: Bundle) -> list[RawViolation]:
        calls.append(str(current["target_method"]))
        match current["target_method"]:
            case "m1":
                return [violation("A")] * 200 + [violation("B")] * 200
            case "m2":
                return [violation("A")] * 200 + [violation("C")] * 200
            case "m3":
                return [violation("D")] * 200
            case _:
                return [violation("Z")] * 200

    install_policy_input(monkeypatch, bundles=bundles, evaluator=evaluate)

    result = integration.evaluate_policies(max_total_violations=100, max_per_violation_id=25)

    assert result.get("truncated") is True
    assert len(result["violations"]) <= 100
    assert all(count <= 25 for count in count_violation_ids(result["violations"]).values())
    assert sorted(calls) == ["m1", "m2", "m3", "m4"]


def test_policy_results_expose_top_level_code_snippet_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    source_code = "public void m1() {}"
    method_bundle = (
        BundleBuilder()
        .with_target_method("m1")
        .with_file_path("f1")
        .with_source_code(source_code)
        .with_vector_context([])
        .with_line_numbers(10, 12)
        .with_analysis_flags({"md5_detected": False})
        .build()
    )
    install_policy_input(monkeypatch, bundles=[method_bundle], evaluator=lambda _bundle: [violation("A")])

    result = integration.evaluate_policies()

    finding = result["violations"][0]
    assert finding["code_snippet"] == source_code
    assert finding["snippet_available"] is True
    assert finding["snippet_start_line"] == 10
    assert finding["snippet_end_line"] == 12
    assert finding["evidence"]["source_code"] == source_code


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        (
            "ISO-A.10-WEAK-HASH",
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Bounded weak-hash replacements such as MD5 or SHA-1 to SHA-256 can be applied with minimal local edits.",
                "safe_refusal_possible": False,
            },
        ),
        (
            "ISO-A.10-WEAK-RANDOM",
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Local randomness upgrades can often be made safely with narrow replacements to SecureRandom-based APIs.",
                "safe_refusal_possible": True,
            },
        ),
        (
            "ISO-A.9.4.1",
            {
                "supported": False,
                "support_tier": "manual",
                "reason_code": "unsupported_rule_for_auto_fix",
                "strategy": None,
                "preview_available": False,
                "verify_available": False,
                "ui_apply_mode": "dry_run",
                "rationale": "Access-control findings remain manual-review because endpoint semantics cannot be safely inferred from method-local evidence.",
                "safe_refusal_possible": False,
            },
        ),
    ],
)
def test_policy_results_include_remediation_capability_metadata(
    monkeypatch: pytest.MonkeyPatch,
    rule_id: str,
    expected: dict[str, Any],
) -> None:
    method_bundle = bundle("m1", file_path="src/main/java/F1.java")
    install_policy_input(monkeypatch, bundles=[method_bundle], evaluator=lambda _bundle: [violation(rule_id)])

    result = integration.evaluate_policies()

    assert result["violations"][0]["remediation"] == expected


def test_policy_results_can_be_filtered_by_rule_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    bundles = [
        bundle("m1", file_path="src/main/java/F1.java"),
        bundle("m2", file_path="src/main/java/F2.java"),
    ]

    def evaluate(current: Bundle) -> list[RawViolation]:
        if current["target_method"] == "m1":
            return [violation("ISO-A.10-WEAK-HASH", reason="hash")]
        return [violation("ISO-A.8-SQL-INJECTION", reason="sql")]

    install_policy_input(monkeypatch, bundles=bundles, evaluator=evaluate)

    result = integration.evaluate_policies(rule_ids=["ISO-A.10-WEAK-HASH"])

    assert [item["violation_id"] for item in result["violations"]] == ["ISO-A.10-WEAK-HASH"]


def test_one_failing_bundle_does_not_abort_whole_run(monkeypatch: pytest.MonkeyPatch) -> None:
    bundles = [
        bundle("good", file_path="g"),
        bundle("bad", file_path="b"),
    ]

    def evaluate(current: Bundle) -> list[RawViolation]:
        if current["target_method"] == "bad":
            raise RuntimeError("OPA evaluation failed for bad")
        return [violation("A")]

    install_policy_input(monkeypatch, bundles=bundles, evaluator=evaluate)

    result = integration.evaluate_policies()

    assert len(result["violations"]) == 1
    assert "error" not in result
    assert result.get("failed_bundle_count") == 1
    assert result["failed_bundles"][0]["target_method"] == "bad"
