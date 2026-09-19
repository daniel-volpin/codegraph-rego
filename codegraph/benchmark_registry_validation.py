from __future__ import annotations

from pathlib import Path

from codegraph.benchmark_registry_models import PolicyRegistry, PolicyRuleSpec
from codegraph.policy.runtime.contracts import EVIDENCE_FIELD_ALIAS_MAP


def first_duplicate(values: list[str]) -> str | None:
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        if value in seen:
            return value
        seen.add(value)
    return None


def validate_rule_module(rule: PolicyRuleSpec, project_root: Path) -> None:
    rego_module_path = (project_root / rule.rego_module).resolve()
    if rego_module_path.suffix != ".rego":
        raise ValueError(f"Policy registry rule {rule.id} must reference a .rego module: {rule.rego_module}")
    if project_root.resolve() not in rego_module_path.parents:
        raise ValueError(f"Policy registry rule {rule.id} references a module outside the repository.")
    if not rego_module_path.is_file():
        raise ValueError(f"Policy registry rule {rule.id} references a missing module: {rule.rego_module}")


def validate_engine_rule(rule: PolicyRuleSpec, engine_name: str) -> None:
    from codegraph.policy.engines import get_engine  # noqa: PLC0415

    engine = get_engine(engine_name)
    if engine is None:
        raise ValueError(f"Policy registry rule {rule.id} has unknown evidence_source: {engine_name}")
    if rule.id not in engine.discover_rule_ids():
        raise ValueError(
            f"Policy registry rule {rule.id} declares evidence_source={engine.name} but no rule with that id "
            f"was found in that engine's rule set."
        )


def validate_rule(
    rule: PolicyRuleSpec,
    *,
    project_root: Path,
    rule_ids: set[str],
    alias_ids: set[str],
    iso_rule_ids: set[str],
) -> None:
    if not rule.id:
        raise ValueError("Policy registry rules must include a non-empty id.")
    if not rule.iso_rule_id:
        raise ValueError(f"Policy registry rule {rule.id} must include a non-empty ISO rule id.")
    if rule.iso_rule_id in iso_rule_ids:
        raise ValueError(f"Policy registry contains duplicate ISO rule id: {rule.iso_rule_id}")
    iso_rule_ids.add(rule.iso_rule_id)
    if rule.evidence_source == "opa":
        validate_rule_module(rule, project_root)
    else:
        validate_engine_rule(rule, rule.evidence_source)

    for evidence_field in rule.evidence_fields:
        if evidence_field not in EVIDENCE_FIELD_ALIAS_MAP:
            raise ValueError(f"Policy registry rule {rule.id} references an unknown evidence field: {evidence_field}")

    for alias in rule.alias_ids:
        if alias in rule_ids:
            raise ValueError(f"Policy registry alias {alias} collides with a rule id.")
        if alias in alias_ids:
            raise ValueError(f"Policy registry contains duplicate alias id: {alias}")
        alias_ids.add(alias)


def validate_registry(registry: PolicyRegistry, project_root: Path) -> PolicyRegistry:
    all_rule_ids = [rule.id for rule in registry.rules]
    duplicate_rule_id = first_duplicate(all_rule_ids)
    if duplicate_rule_id:
        raise ValueError(f"Policy registry contains duplicate rule id: {duplicate_rule_id}")

    rule_ids = set(all_rule_ids)
    alias_ids: set[str] = set()
    iso_rule_ids: set[str] = set()
    category_ids: set[str] = set()

    for rule in registry.rules:
        validate_rule(
            rule,
            project_root=project_root,
            rule_ids=rule_ids,
            alias_ids=alias_ids,
            iso_rule_ids=iso_rule_ids,
        )

    for category in registry.categories:
        if not category.category_id:
            raise ValueError("Policy registry categories must include a non-empty category id.")
        if category.category_id in category_ids:
            raise ValueError(f"Policy registry contains duplicate category id: {category.category_id}")
        category_ids.add(category.category_id)

    missing = sorted(
        rule_id for category in registry.categories for rule_id in category.rego_rule_ids if rule_id not in rule_ids
    )
    if missing:
        raise ValueError(f"Policy registry categories reference unknown rule ids: {missing}")
    return registry
