"""Tool calling and OpenAI function definition dataclasses for LLM agents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolDefinition:
    """Specification of an executable tool in OpenAI function-calling format."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai_dict(self) -> dict[str, Any]:
        """Format as standard OpenAI function tool schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class ToolCall:
    """Represents a tool execution invocation emitted by an LLM."""

    id: str
    name: str
    arguments: dict[str, Any]
    type: str = "function"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "function": {
                "name": self.name,
                "arguments": json.dumps(self.arguments) if isinstance(self.arguments, dict) else str(self.arguments),
            },
        }


@dataclass(frozen=True)
class ToolResult:
    """Carries the outcome of executing a tool call back to the LLM conversation."""

    call_id: str
    name: str
    output: str
    success: bool = True
    error: str | None = None

    def to_tool_message(self) -> dict[str, str]:
        """Format as an OpenAI role='tool' conversation message."""
        return {
            "role": "tool",
            "tool_call_id": self.call_id,
            "content": self.output if self.success else f"Error executing {self.name}: {self.error or self.output}",
        }


@dataclass
class ChatCompletionResponse:
    """Typed envelope representing chat completion output with optional tool calls."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_response: dict[str, Any] | None = None
    finish_reason: str | None = None

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @classmethod
    def from_response(cls, raw: Any) -> ChatCompletionResponse:
        """Parse text content and ToolCall objects from SDK responses, dicts, or strings."""
        if not raw:
            return cls()

        # Direct instance pass-through
        if isinstance(raw, cls):
            return raw

        content, tool_calls, finish_reason = _extract_response_components(raw)
        return cls(
            content=content,
            tool_calls=tool_calls,
            raw_response=raw if isinstance(raw, dict) else None,
            finish_reason=finish_reason,
        )


def _extract_function_args(raw_arguments: Any) -> dict[str, Any]:
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if isinstance(raw_arguments, str) and raw_arguments.strip():
        try:
            parsed = json.loads(raw_arguments)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {}


def _parse_single_tool_call(tc: Any) -> ToolCall | None:
    call_id = getattr(tc, "id", None) or (tc.get("id") if isinstance(tc, dict) else None)
    fn = getattr(tc, "function", None) or (tc.get("function") if isinstance(tc, dict) else None)
    call_type = getattr(tc, "type", "function") or (tc.get("type", "function") if isinstance(tc, dict) else "function")

    fn_name = (
        getattr(fn, "name", None)
        or (fn.get("name") if isinstance(fn, dict) else None)
        or getattr(tc, "name", None)
        or (tc.get("name") if isinstance(tc, dict) else None)
    )
    if not fn_name:
        return None

    raw_args = (
        getattr(fn, "arguments", None)
        or (fn.get("arguments") if isinstance(fn, dict) else None)
        or getattr(tc, "arguments", None)
        or (tc.get("arguments") if isinstance(tc, dict) else None)
    )
    args = _extract_function_args(raw_args)

    return ToolCall(
        id=str(call_id or ""),
        name=str(fn_name),
        arguments=args,
        type=str(call_type),
    )


def _extract_response_components(raw: Any) -> tuple[str, list[ToolCall], str | None]:
    # 1. Handle SDK objects or dicts with choices
    choices = getattr(raw, "choices", None) or (raw.get("choices") if isinstance(raw, dict) else None)
    if choices and len(choices) > 0:
        first_choice = choices[0]
        msg = getattr(first_choice, "message", None) or (
            first_choice.get("message") if isinstance(first_choice, dict) else None
        )
        finish_reason = getattr(first_choice, "finish_reason", None) or (
            first_choice.get("finish_reason") if isinstance(first_choice, dict) else None
        )

        content = ""
        tool_calls: list[ToolCall] = []

        if msg is not None:
            raw_content = getattr(msg, "content", None) or (
                msg.get("content") if isinstance(msg, dict) else None
            )
            content = str(raw_content or "")

            raw_tool_calls = getattr(msg, "tool_calls", None) or (
                msg.get("tool_calls") if isinstance(msg, dict) else None
            )
            for raw_tc in raw_tool_calls or []:
                tc = _parse_single_tool_call(raw_tc)
                if tc is not None:
                    tool_calls.append(tc)

        return content, tool_calls, str(finish_reason) if finish_reason else None

    # 2. Handle plain text responses
    if isinstance(raw, str):
        content = raw
        tool_calls = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "name" in parsed:
                tc = _parse_single_tool_call(parsed)
                if tc is not None:
                    tool_calls.append(tc)
        except json.JSONDecodeError:
            pass
        return content, tool_calls, None

    return "", [], None


def parse_tool_calls_from_response(raw_response: Any) -> tuple[str, list[ToolCall]]:
    """Parse text content and ToolCall objects from raw OpenAI / compatibility responses."""
    resp = ChatCompletionResponse.from_response(raw_response)
    return resp.content, resp.tool_calls
