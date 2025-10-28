from codegraph.policy.service import evaluate as evaluate_policies
from codegraph.policy.service import catalog as get_policy_catalog_entries
from codegraph.llm.integration import explain_policy_violations
from codegraph.api.models import (
    PolicyViolation,
    ControlMetadata,
    EvaluateResponse,
    EvaluateWithLLMResponse,
    LLMEnrichedItem,
    PolicyCatalogResponse,
)
import logging

logger = logging.getLogger(__name__)

def handle_policy_evaluate() -> EvaluateResponse:
    result = evaluate_policies()
    violations = [PolicyViolation(**v) for v in result.get("violations", [])]
    catalog_items = [ControlMetadata(**c) for c in result.get("catalog", [])]
    return EvaluateResponse(
        violations=violations,
        opa_output=result.get("opa_output"),
        catalog=catalog_items,
    )

def handle_policy_evaluate_with_llm(limit: int = 10, model: str | None = None) -> EvaluateWithLLMResponse:
    res = evaluate_policies()
    vio = res.get("violations", [])[:limit]
    enriched_raw = explain_policy_violations(vio, max_items=limit, model=model)
    violations_modeled = [PolicyViolation(**v) for v in vio]
    enriched_modeled = []
    for item in enriched_raw:
        pv = PolicyViolation(**item.get("violation", {}))
        enriched_modeled.append(
            LLMEnrichedItem(
                violation=pv,
                snippet=item.get("snippet", ""),
                explanation=item.get("explanation", ""),
            )
        )
    return EvaluateWithLLMResponse(violations=violations_modeled, enriched=enriched_modeled)

def handle_policy_catalog() -> PolicyCatalogResponse:
    controls = get_policy_catalog_entries()
    controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
    return PolicyCatalogResponse(controls=[ControlMetadata(**c) for c in controls_sorted])
