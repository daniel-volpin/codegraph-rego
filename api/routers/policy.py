from fastapi import APIRouter
from fastapi import Query
from fastapi.responses import JSONResponse
from api.models.validation import (
    PolicyEvaluateResponse,
    PolicyCatalogResponse,
    PolicyEvaluateWithLLMRequest,
    PolicyExplainOneRequest,
    PolicyExplainOneResponse,
    PolicyReviewCreateRequest,
    PolicyReviewCreateResponse,
    PolicyReviewListResponse,
)
from codegraph.policy.service import evaluate as evaluate_policies, catalog as get_policy_catalog_entries
from codegraph.llm.integration import (
    explain_policy_violations,
    generate_policy_explanation_structured,
    render_policy_explanation_structured,
)
from codegraph.llm.client import LLMUnavailableError
from codegraph.config import LLM_MODEL, settings
from codegraph.policy.review_store import append_review_jsonl, resolve_review_store_path
import logging
from collections import deque
import json

router = APIRouter()
logger = logging.getLogger("codegraph.api.routers.policy")


@router.get("/policy/evaluate", response_model=PolicyEvaluateResponse)
async def policy_evaluate(
    max_bundles: int | None = Query(default=None, ge=1, le=5000),
    max_total_violations: int | None = Query(default=None),
    max_per_violation_id: int | None = Query(default=None),
    rule_ids: list[str] | None = Query(default=None),
):
    try:
        result = evaluate_policies(
            max_bundles=max_bundles,
            max_total_violations=max_total_violations,
            max_per_violation_id=max_per_violation_id,
            rule_ids=rule_ids,
        )
        status = 200 if "violations" in result or "opa_output" in result else 500
        return JSONResponse(result, status_code=status)
    except Exception as e:
        logger.error(f"Policy evaluation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/policy/evaluate_with_llm", response_model=PolicyEvaluateResponse)
async def policy_evaluate_with_llm(payload: PolicyEvaluateWithLLMRequest):
    res = evaluate_policies(
        max_bundles=payload.max_bundles,
        max_total_violations=payload.max_total_violations,
        max_per_violation_id=payload.max_per_violation_id,
        rule_ids=payload.rule_ids,
    )
    if "violations" not in res:
        return JSONResponse(res, status_code=500)
    safe_limit = max(1, payload.limit)
    safe_limit = min(safe_limit, 100)
    vio = (res.get("violations", []) or [])[:safe_limit]
    enriched = explain_policy_violations(
        vio,
        max_items=safe_limit,
        model=(payload.model or "").strip() or LLM_MODEL,
    )
    return JSONResponse({"violations": vio, "enriched": enriched})


@router.post("/policy/explain_one", response_model=PolicyExplainOneResponse)
async def policy_explain_one(payload: PolicyExplainOneRequest):
    model = (payload.model or "").strip() or settings.llm_model
    try:
        explanation_structured = generate_policy_explanation_structured(
            payload.violation,
            include_graph_context=bool(payload.include_graph_context),
            model=model,
            raise_on_error=True,
        )
        explanation = render_policy_explanation_structured(explanation_structured)
        return JSONResponse(
            {
                "status": "OK",
                "explanation": explanation,
                "explanation_structured": explanation_structured,
                "model": model,
                "include_graph_context": bool(payload.include_graph_context),
            },
            status_code=200,
        )
    except LLMUnavailableError as exc:
        # Expected runtime error when a local LLM server (e.g. LM Studio) isn't running or credentials are missing.
        logger.info("Explain-one LLM unavailable: %s", exc)
        return JSONResponse(
            {
                "status": "ERROR",
                "error": str(exc),
                "model": model,
                "include_graph_context": bool(payload.include_graph_context),
            },
            status_code=503,
        )
    except Exception as exc:
        logger.exception("Explain-one failed: %s", exc)
        return JSONResponse(
            {
                "status": "ERROR",
                "error": str(exc),
                "model": model,
                "include_graph_context": bool(payload.include_graph_context),
            },
            status_code=500,
        )


@router.post("/policy/reviews", response_model=PolicyReviewCreateResponse)
async def policy_create_review(payload: PolicyReviewCreateRequest):
    result = append_review_jsonl(
        store_path=settings.ui_review_store_path,
        label=payload.label,
        notes=payload.notes,
        violation=payload.violation,
        explanation=payload.explanation,
        llm_model=payload.llm_model or settings.llm_model,
        include_graph_context=bool(payload.include_graph_context),
        remediation_preview=payload.remediation_preview,
        remediation_apply=payload.remediation_apply,
    )
    status = (result.status or "ERROR").upper()
    http_status = 200 if status == "OK" else 500
    return JSONResponse(
        {
            "status": status,
            "review_id": result.review_id,
            "store_path": result.store_path,
            "scrub_warnings": result.scrub_warnings or [],
            "error": result.error,
        },
        status_code=http_status,
    )


@router.get("/policy/reviews", response_model=PolicyReviewListResponse)
async def policy_list_reviews(
    violation_key: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    resolved, error = resolve_review_store_path(settings.ui_review_store_path)
    if error:
        return JSONResponse({"status": "ERROR", "error": error, "reviews": []}, status_code=500)
    assert resolved is not None
    if not resolved.exists():
        return JSONResponse({"status": "OK", "error": None, "reviews": []}, status_code=200)

    buffer: deque[dict] = deque(maxlen=limit)
    try:
        with open(resolved.as_posix(), "r", encoding="utf-8") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                key = obj.get("violation_key")
                if violation_key and key != violation_key:
                    continue
                buffer.append(
                    {
                        "review_id": obj.get("review_id"),
                        "created_at": obj.get("created_at"),
                        "violation_key": key,
                        "label": obj.get("label"),
                        "notes": obj.get("notes"),
                    }
                )
    except Exception as exc:
        logger.exception("List reviews failed: %s", exc)
        return JSONResponse({"status": "ERROR", "error": str(exc), "reviews": []}, status_code=500)

    return JSONResponse({"status": "OK", "error": None, "reviews": list(buffer)}, status_code=200)


@router.get("/policy/catalog", response_model=PolicyCatalogResponse)
async def policy_catalog():
    try:
        controls = get_policy_catalog_entries()
        controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
        return JSONResponse({"controls": controls_sorted})
    except Exception as exc:
        logger.error(f"Policy catalog error: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)
