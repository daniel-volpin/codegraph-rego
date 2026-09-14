"""Registry of non-OPA detection engines.

Engine identity is a property of a rule, not of the architecture: a rule
declares its owning engine via ``evidence_source`` in the policy registry, and
everything that evaluates or re-verifies findings routes through here rather
than naming a specific engine. Adding an engine means registering it once.

OPA/Rego is deliberately absent. It is evaluated over evidence bundles by
``codegraph.policy.integration`` and does not implement this contract.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from neo4j import Driver

from codegraph.config import settings


class RuleIdDiscovery(Protocol):
    def __call__(self) -> set[str]: ...


@dataclass(frozen=True)
class DetectionEngine:
    """One pluggable detection engine.

    ``evaluate`` returns violations already shaped like OPA-native ones (the
    SARIF bridge does that anchoring). ``verify_candidate`` re-checks a single
    candidate compilation unit and must raise rather than return empty when the
    engine cannot run, so a remediation gate fails closed.
    """

    name: str
    discover_rule_ids: RuleIdDiscovery
    evaluate: Callable[..., list[dict[str, Any]]]
    verify_candidate: Callable[..., list[dict[str, Any]]]


def _opengrep_engine() -> DetectionEngine:
    from codegraph.policy import opengrep_bridge  # noqa: PLC0415 - avoids an import cycle

    return DetectionEngine(
        name="opengrep",
        discover_rule_ids=opengrep_bridge.discover_rule_ids,
        evaluate=opengrep_bridge.evaluate_opengrep_rules,
        verify_candidate=opengrep_bridge.verify_candidate_source,
    )


_ENGINE_FACTORIES: Mapping[str, Callable[[], DetectionEngine]] = {
    "opengrep": _opengrep_engine,
}

# Engines are constructed lazily and cached: importing a bridge pulls in its
# subprocess and SARIF dependencies, which the common OPA-only path does not need.
_CACHE: dict[str, DetectionEngine] = {}


def known_evidence_sources() -> frozenset[str]:
    """Valid ``evidence_source`` values, including OPA."""
    return frozenset({"opa", *_ENGINE_FACTORIES})


def get_engine(name: str | None) -> DetectionEngine | None:
    if not name or name not in _ENGINE_FACTORIES:
        return None
    if name not in _CACHE:
        _CACHE[name] = _ENGINE_FACTORIES[name]()
    return _CACHE[name]


def iter_engines() -> list[DetectionEngine]:
    """Every enabled engine, in a stable order."""
    if not settings.detection_engines_enabled:
        return []
    return [engine for name in sorted(_ENGINE_FACTORIES) if (engine := get_engine(name))]


def evaluate_all(
    *,
    workspace_root: str | None,
    neo4j_driver: Driver,
    on_error: Callable[[str, Exception], None] | None = None,
) -> list[dict[str, Any]]:
    """Run every registered engine and return the concatenated violations.

    An engine that raises is reported through *on_error* and contributes
    nothing; callers decide whether that is tolerable. Results are not
    deduplicated here — see ``dedupe_violations``.
    """
    violations: list[dict[str, Any]] = []
    for engine in iter_engines():
        try:
            violations.extend(engine.evaluate(workspace_root=workspace_root, neo4j_driver=neo4j_driver))
        except Exception as exc:
            if on_error is None:
                raise
            on_error(engine.name, exc)
    return violations


def dedupe_violations(violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse findings that share ``(rule_id, method_key)``.

    Two engines may cover one rule during a transition; without this the same
    finding would be counted twice. Findings with no method_key cannot be
    proven identical and are all kept.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for violation in violations:
        method_key = violation.get("method_key")
        if not method_key:
            unique.append(violation)
            continue
        key = (str(violation.get("violation_id") or ""), str(method_key))
        if key in seen:
            continue
        seen.add(key)
        unique.append(violation)
    return unique
