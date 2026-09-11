import asyncio
import json
import logging
from collections import deque

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from api.models.validation import (
    PolicyCatalogResponse,
    PolicyEvaluateResponse,
    PolicyEvaluateWithLLMRequest,
    PolicyExplainOneRequest,
    PolicyExplainOneResponse,
    PolicyReviewCreateRequest,
    PolicyReviewCreateResponse,
    PolicyReviewListResponse,
)
from codegraph.config import settings
from codegraph.llm.client import LLMUnavailableError
from codegraph.llm.integration import (
    explain_policy_violations,
    generate_policy_explanation,
    generate_policy_explanation_structured,
    render_policy_explanation_structured,
)
from codegraph.policy.review_store import append_review_jsonl, resolve_review_store_path
from codegraph.policy.service import (
    catalog as get_policy_catalog_payload,
)
from codegraph.policy.service import (
    evaluate as evaluate_policies,
)
from codegraph.policy.service import (
    export_sarif,
)

router = APIRouter()
logger = logging.getLogger("codegraph.api.routers.policy")


@router.get("/policy/evaluate", response_model=PolicyEvaluateResponse)
async def policy_evaluate(
    max_bundles: int | None = Query(default=None, ge=1, le=5000),
    max_total_violations: int | None = Query(default=None),
    max_per_violation_id: int | None = Query(default=None),
    rule_ids: list[str] | None = Query(default=None),
):
    # OPA subprocess + Neo4j: blocking; run on a worker thread.
    result = await asyncio.to_thread(
        evaluate_policies,
        max_bundles=max_bundles,
        max_total_violations=max_total_violations,
        max_per_violation_id=max_per_violation_id,
        rule_ids=rule_ids,
    )
    status = 200 if not result.get("error") and ("violations" in result or "opa_output" in result) else 500
    return JSONResponse(result, status_code=status)


@router.get("/policy/export/sarif")
async def policy_export_sarif(rule_ids: list[str] | None = Query(default=None)):
    """Export security policy findings in standard OASIS SARIF v2.1.0 JSON format."""
    sarif_doc = await asyncio.to_thread(export_sarif, rule_ids=rule_ids)
    return JSONResponse(
        sarif_doc,
        headers={"Content-Type": "application/sarif+json; charset=utf-8"},
    )


@router.post("/policy/evaluate_with_llm", response_model=PolicyEvaluateResponse)
async def policy_evaluate_with_llm(payload: PolicyEvaluateWithLLMRequest):
    res = await asyncio.to_thread(
        evaluate_policies,
        max_bundles=payload.max_bundles,
        max_total_violations=payload.max_total_violations,
        max_per_violation_id=payload.max_per_violation_id,
        rule_ids=payload.rule_ids,
    )
    if res.get("error") or "violations" not in res:
        return JSONResponse(res, status_code=500)
    safe_limit = max(1, payload.limit)
    safe_limit = min(safe_limit, 100)
    vio = (res.get("violations", []) or [])[:safe_limit]
    enriched = await asyncio.to_thread(
        explain_policy_violations,
        vio,
        max_items=safe_limit,
        model=(payload.model or "").strip() or settings.llm_model,
    )
    return JSONResponse({**res, "enriched": enriched})


@router.post("/policy/explain_one", response_model=PolicyExplainOneResponse)
async def policy_explain_one(payload: PolicyExplainOneRequest):
    model = (payload.model or "").strip() or settings.llm_model
    try:
        try:
            explanation_structured = await asyncio.to_thread(
                generate_policy_explanation_structured,
                payload.violation,
                include_graph_context=bool(payload.include_graph_context),
                model=model,
                raise_on_error=True,
            )
            explanation = render_policy_explanation_structured(explanation_structured)
        except ValueError as exc:
            logger.warning("Explain-one structured parse failed; falling back to plain explanation: %s", exc)
            explanation_structured = None
            explanation = await asyncio.to_thread(
                generate_policy_explanation,
                payload.violation,
                include_graph_context=bool(payload.include_graph_context),
                structured_output=False,
                model=model,
                raise_on_error=True,
            )
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
        logger.exception("Explain-one failed", extra={"err": str(exc), "err_type": type(exc).__name__})
        raise


@router.post("/policy/reviews", response_model=PolicyReviewCreateResponse)
async def policy_create_review(payload: PolicyReviewCreateRequest):
    result = await asyncio.to_thread(
        append_review_jsonl,
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

    def _scan_jsonl() -> deque[dict]:
        buffer: deque[dict] = deque(maxlen=limit)
        with open(resolved.as_posix(), encoding="utf-8") as handle:
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
        return buffer

    try:
        buffer = await asyncio.to_thread(_scan_jsonl)
    except Exception as exc:
        logger.exception("List reviews failed", extra={"err": str(exc), "err_type": type(exc).__name__})
        raise

    return JSONResponse({"status": "OK", "error": None, "reviews": list(buffer)}, status_code=200)


@router.get("/policy/catalog", response_model=PolicyCatalogResponse)
async def policy_catalog():
    payload = await asyncio.to_thread(get_policy_catalog_payload)
    controls = payload.get("controls", [])
    controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
    response = dict(payload)
    response["controls"] = controls_sorted
    return JSONResponse(response)
