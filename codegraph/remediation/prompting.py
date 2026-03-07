from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
from typing import Any, Dict, List, Optional


LOGGER = logging.getLogger(__name__)
_MAX_VECTOR_CONTEXT_ITEMS = 8
_MAX_GRAPH_CALLS = 20
_MAX_GRAPH_CALLERS = 20
_MAX_GRAPH_FIELDS = 12


@dataclass(frozen=True)
class RemediationTaskSpec:
    rule_id: str
    objective: str
    allowed_transformations: List[str]
    non_goals: List[str]
    extra_examples: List[str] = field(default_factory=list)


class RemediationPromptTemplate:
    TASK_SPEC_BEGIN = "BEGIN_TASK_SPEC_JSON"
    TASK_SPEC_END = "END_TASK_SPEC_JSON"

    VIOLATION_BEGIN = "BEGIN_VIOLATION_JSON"
    VIOLATION_END = "END_VIOLATION_JSON"

    CONTROL_BEGIN = "BEGIN_CONTROL_METADATA_JSON"
    CONTROL_END = "END_CONTROL_METADATA_JSON"

    SOURCE_BEGIN = "BEGIN_SOURCE_SNIPPET"
    SOURCE_END = "END_SOURCE_SNIPPET"

    GRAPH_BEGIN = "BEGIN_GRAPH_CONTEXT_JSON"
    GRAPH_END = "END_GRAPH_CONTEXT_JSON"

    VECTOR_BEGIN = "BEGIN_VECTOR_CONTEXT_JSON"
    VECTOR_END = "END_VECTOR_CONTEXT_JSON"

    PREV_ERR_BEGIN = "BEGIN_PREVIOUS_ERRORS"
    PREV_ERR_END = "END_PREVIOUS_ERRORS"

    @staticmethod
    def system_prompt() -> str:
        return (
            "You are a remediation agent for Java code.\n"
            "Use ONLY the evidence provided in the user message blocks.\n"
            "Preserve behavior and the method signature. Make the smallest change that satisfies the task.\n\n"
            "Return a JSON object only with exactly these fields:\n"
            "- decision: \"replace_method\" or \"no_fix\"\n"
            "- replacement_method_lines: array of strings\n"
            "- reason: string\n\n"
            "If decision is \"replace_method\", replacement_method_lines MUST contain the COMPLETE replacement method "
            "with exactly one source line per array element, starting from annotations if present and then the access "
            "modifier (public/private/protected), return type, method name, parameters, the opening brace '{', the "
            "ENTIRE method body with ALL lines (both changed and unchanged), and the closing brace '}'.\n"
            "If decision is \"no_fix\", reason MUST explain why a safe minimal fix is not possible.\n"
            "When a field does not apply, return an empty array for replacement_method_lines and an empty string for reason.\n"
            "Do not put newline escape sequences inside a single string. Use one line per array element.\n\n"
            "Do not output markdown, code fences, diffs, prose, backticks, or any text outside the JSON object."
        )

    @classmethod
    def format_task_spec_json(cls, spec: RemediationTaskSpec) -> str:
        examples = list(spec.extra_examples or [])
        if len(examples) > 1:
            LOGGER.warning(
                "Task spec extra_examples has %d items; truncating to 1 for determinism.",
                len(examples),
            )
            examples = examples[:1]

        payload = {
            "rule_id": spec.rule_id,
            "objective": spec.objective,
            "allowed_transformations": list(spec.allowed_transformations or []),
            "non_goals": list(spec.non_goals or []),
            "extra_examples": examples,
        }
        return "\n".join(
            [
                cls.TASK_SPEC_BEGIN,
                json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=False),
                cls.TASK_SPEC_END,
            ]
        )

    @classmethod
    def _build_violation_payload(cls, context: Dict[str, Any]) -> Dict[str, Any]:
        violation = context.get("violation") or {}
        return {
            "violation_id": violation.get("violation_id") or violation.get("id") or context.get("rule_id"),
            "reason": violation.get("reason"),
            "severity": violation.get("severity"),
            "target_method": context.get("target_method") or violation.get("target_method") or violation.get("method"),
            "file_path": context.get("file_path") or violation.get("file_path"),
        }

    @classmethod
    def _build_control_payload(cls, catalog_entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": catalog_entry.get("id"),
            "title": catalog_entry.get("title"),
            "summary": catalog_entry.get("summary"),
            "control": catalog_entry.get("control"),
            "reference": catalog_entry.get("reference"),
        }

    @classmethod
    def _build_graph_payload(cls, graph_context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "annotations": list(graph_context.get("annotations") or []),
            "calls": list(graph_context.get("calls") or [])[:_MAX_GRAPH_CALLS],
            "callers": list(graph_context.get("callers") or [])[:_MAX_GRAPH_CALLERS],
            "uses_fields": list(graph_context.get("uses_fields") or [])[:_MAX_GRAPH_FIELDS],
        }

    @classmethod
    def build_user_prompt(
        cls,
        context: Dict[str, Any],
        spec: RemediationTaskSpec,
        previous_errors: Optional[List[str]] = None,
    ) -> str:
        evidence = context.get("evidence") or {}
        catalog_entry = context.get("catalog_entry") or {}

        target_method = context.get("target_method") or context.get("method") or "unknown"
        file_path = context.get("file_path") or "unknown"
        source_code = (evidence.get("source_code") or "").rstrip()
        graph_context = cls._build_graph_payload(evidence.get("graph_context") or {})
        vector_context = list(evidence.get("vector_context") or [])[:_MAX_VECTOR_CONTEXT_ITEMS]

        violation_json = json.dumps(cls._build_violation_payload(context), indent=2, ensure_ascii=True, sort_keys=True)
        control_json = json.dumps(cls._build_control_payload(catalog_entry), indent=2, ensure_ascii=True, sort_keys=True)
        graph_json = json.dumps(graph_context, indent=2, ensure_ascii=True, sort_keys=True)
        vector_json = json.dumps(vector_context, indent=2, ensure_ascii=True, sort_keys=True)

        sections: List[str] = []
        sections.append(f"FILE_PATH: {file_path}")
        sections.append(f"TARGET_METHOD: {target_method}")
        sections.append("")
        sections.append(cls.format_task_spec_json(spec))
        sections.append("")
        sections.extend([cls.VIOLATION_BEGIN, violation_json, cls.VIOLATION_END])
        sections.append("")
        sections.extend([cls.CONTROL_BEGIN, control_json, cls.CONTROL_END])
        sections.append("")
        sections.extend([cls.SOURCE_BEGIN, source_code or "<empty>", cls.SOURCE_END])
        sections.append("")
        sections.extend([cls.GRAPH_BEGIN, graph_json, cls.GRAPH_END])
        sections.append("")
        sections.extend([cls.VECTOR_BEGIN, vector_json, cls.VECTOR_END])

        errors_note = "\n".join(previous_errors or [])
        if errors_note:
            sections.append("")
            sections.extend([cls.PREV_ERR_BEGIN, errors_note, cls.PREV_ERR_END])

        return "\n".join(sections)

    @classmethod
    def build_messages(
        cls,
        *,
        context: Dict[str, Any],
        spec: RemediationTaskSpec,
        previous_errors: Optional[List[str]] = None,
    ) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": cls.system_prompt()},
            {
                "role": "user",
                "content": cls.build_user_prompt(context, spec, previous_errors),
            },
        ]


def build_remediation_response_format() -> Dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "remediation_generation",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["replace_method", "no_fix"],
                    },
                    "replacement_method_lines": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "reason": {
                        "type": "string",
                    },
                },
                "required": ["decision", "replacement_method_lines", "reason"],
            },
        },
    }
