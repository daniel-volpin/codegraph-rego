from fastapi import APIRouter
from fastapi.responses import JSONResponse
from api.models.validation import PolicyEvaluateResponse, PolicyCatalogResponse
from codegraph.policy.service import evaluate as evaluate_policies, catalog as get_policy_catalog_entries
from codegraph.llm.integration import explain_policy_violations
from codegraph.config import LLM_MODEL
import logging

router = APIRouter()
logger = logging.getLogger("codegraph.api.routers.policy")

@router.get("/policy/evaluate", response_model=PolicyEvaluateResponse)
async def policy_evaluate():
    try:
        result = evaluate_policies()
        status = 200 if "violations" in result or "opa_output" in result else 500
        return JSONResponse(result, status_code=status)
    except Exception as e:
        logger.error(f"Policy evaluation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@router.post("/policy/evaluate_with_llm", response_model=PolicyEvaluateResponse)
async def policy_evaluate_with_llm(limit: int = 10, model: str | None = None):
    res = evaluate_policies()
    if "violations" not in res:
        return JSONResponse(res, status_code=500)
    vio = res.get("violations", [])[:limit]
    enriched = explain_policy_violations(vio, max_items=limit, model=model or LLM_MODEL)
    return JSONResponse({"violations": vio, "enriched": enriched})

@router.get("/policy/catalog", response_model=PolicyCatalogResponse)
async def policy_catalog():
    try:
        controls = get_policy_catalog_entries()
        controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
        return JSONResponse({"controls": controls_sorted})
    except Exception as exc:
        logger.error(f"Policy catalog error: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)
