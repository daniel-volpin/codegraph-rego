"""Contract tests for the detection-engine plugin registry.

These assert the properties the plugin contract depends on, so an engine
added later cannot quietly violate them: every registry rule routes to a
known engine, findings deduplicate across engines, and an engine failure is
surfaced rather than silently dropping coverage.
"""

from __future__ import annotations

import pytest

from codegraph.benchmark_registry import evidence_source_for_rule_id, load_policy_registry
from codegraph.policy import engines


def test_every_registry_rule_routes_to_a_known_evidence_source() -> None:
    known = engines.known_evidence_sources()
    for rule in load_policy_registry().rules:
        assert rule.evidence_source in known, (
            f"rule {rule.id} declares evidence_source={rule.evidence_source!r}, "
            f"which no engine claims (known: {sorted(known)})"
        )


def test_non_opa_rules_are_discoverable_in_their_engine() -> None:
    """Guards the failure mode where a declared rule silently never fires."""
    checked = 0
    for rule in load_policy_registry().rules:
        engine = engines.get_engine(rule.evidence_source)
        if engine is None:
            continue
        assert rule.id in engine.discover_rule_ids(), f"{rule.id} not found in {engine.name} rule set"
        checked += 1
    assert checked, "expected at least one engine-backed rule"


def test_evidence_source_lookup_handles_aliases_and_unknowns() -> None:
    assert evidence_source_for_rule_id("ISO-A.10-WEAK-HASH") == "opa"
    assert evidence_source_for_rule_id("ISO-A.8-XPATH-INJECTION") == "opengrep"
    assert evidence_source_for_rule_id("ISO-27001-A.9.4.1") == "opa"  # alias
    assert evidence_source_for_rule_id("NO-SUCH-RULE") is None
    assert evidence_source_for_rule_id(None) is None


def test_get_engine_rejects_unknown_names() -> None:
    assert engines.get_engine("opa") is None  # OPA does not implement this contract
    assert engines.get_engine("does-not-exist") is None
    assert engines.get_engine(None) is None


def test_engines_can_be_disabled_for_triage(monkeypatch) -> None:
    """Disabling drops engine-owned coverage; it must be explicit, never implicit."""
    assert engines.iter_engines(), "expected engines enabled by default"
    monkeypatch.setattr(engines.settings, "detection_engines_enabled", False)
    assert engines.iter_engines() == []
    assert engines.evaluate_all(workspace_root=None, neo4j_driver=None) == []


class TestDedupe:
    def test_collapses_same_rule_and_method(self) -> None:
        findings = [
            {"violation_id": "R1", "method_key": "k1"},
            {"violation_id": "R1", "method_key": "k1"},
        ]
        assert len(engines.dedupe_violations(findings)) == 1

    def test_keeps_distinct_methods_and_rules(self) -> None:
        findings = [
            {"violation_id": "R1", "method_key": "k1"},
            {"violation_id": "R1", "method_key": "k2"},
            {"violation_id": "R2", "method_key": "k1"},
        ]
        assert len(engines.dedupe_violations(findings)) == 3

    def test_keeps_findings_without_method_key(self) -> None:
        """Unanchored findings cannot be proven identical, so none are dropped."""
        findings = [{"violation_id": "R1"}, {"violation_id": "R1"}]
        assert len(engines.dedupe_violations(findings)) == 2


class TestEvaluateAll:
    def test_engine_failure_is_reported_not_swallowed(self, monkeypatch) -> None:
        boom = RuntimeError("engine exploded")
        broken = engines.DetectionEngine(
            name="broken",
            discover_rule_ids=lambda: set(),
            evaluate=lambda **_: (_ for _ in ()).throw(boom),
            verify_candidate=lambda **_: [],
        )
        monkeypatch.setattr(engines, "iter_engines", lambda: [broken])

        seen: list[tuple[str, Exception]] = []
        result = engines.evaluate_all(workspace_root=None, neo4j_driver=None, on_error=lambda n, e: seen.append((n, e)))

        assert result == []
        assert seen == [("broken", boom)]

    def test_engine_failure_propagates_without_a_handler(self, monkeypatch) -> None:
        broken = engines.DetectionEngine(
            name="broken",
            discover_rule_ids=lambda: set(),
            evaluate=lambda **_: (_ for _ in ()).throw(RuntimeError("boom")),
            verify_candidate=lambda **_: [],
        )
        monkeypatch.setattr(engines, "iter_engines", lambda: [broken])
        with pytest.raises(RuntimeError, match="boom"):
            engines.evaluate_all(workspace_root=None, neo4j_driver=None)
