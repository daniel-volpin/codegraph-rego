from __future__ import annotations

from typing import Any

from codegraph.config import settings
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.schema.remediation import build_remediation_response_format, parse_structured_generation_response
from codegraph.llm.tasks.remediation import RemediationPromptTemplate, RemediationTaskSpec
from codegraph.remediation.contracts import STRUCTURED_GENERATION_STOPS, build_generation_payload


class RemediationGenerationService:
    def __init__(self, *, llm_client=generate_chat_completion) -> None:
        self._llm_client = llm_client

    def propose_method_edits(
        self,
        *,
        context: dict[str, Any],
        spec: RemediationTaskSpec,
        previous_errors: list[str] | None = None,
    ) -> dict[str, Any]:
        messages = RemediationPromptTemplate.build_messages(context=context, spec=spec, previous_errors=previous_errors)
        model = settings.remediation_llm_model or settings.llm_model
        temperature = (
            settings.remediation_llm_temperature
            if settings.remediation_llm_temperature is not None
            else settings.llm_temperature
        )
        max_tokens = (
            settings.remediation_llm_max_tokens
            if settings.remediation_llm_max_tokens is not None
            else settings.llm_max_tokens_remediation
        )
        ttl_seconds = (
            settings.remediation_llm_model_ttl_seconds
            if settings.remediation_llm_model_ttl_seconds is not None
            else settings.llm_model_ttl_seconds
        )

        try:
            response = self._llm_client(
                messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                ttl_seconds=ttl_seconds,
                stop=STRUCTURED_GENERATION_STOPS,
                response_format=build_remediation_response_format(),
                raise_on_error=True,
            )
        except TypeError:
            response = self._llm_client(messages)

        parsed = parse_structured_generation_response(
            response,
            target_method=context.get("target_method"),
            original_method_lines=(context.get("exact_method_source") or "").splitlines(),
            plan=context.get("remediation_plan"),
        )
        parsed["raw_output"] = response
        parsed["generation"] = build_generation_payload(
            decision=parsed.get("decision"),
            edits=parsed.get("edits"),
            replacement_method_lines=parsed.get("replacement_method_lines"),
            replacement_method_code=parsed.get("replacement_method_code"),
            reason=parsed.get("reason"),
            raw_response_valid=bool(parsed.get("raw_response_valid")),
            schema_error=parsed.get("schema_error"),
        )
        return parsed
