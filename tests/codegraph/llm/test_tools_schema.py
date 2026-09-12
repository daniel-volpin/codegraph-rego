"""Unit tests for tool calling dataclasses and OpenAI response parsing."""

from __future__ import annotations

import unittest

from codegraph.llm.schema.tools import (
    ChatCompletionResponse,
    ToolCall,
    ToolDefinition,
    ToolResult,
    parse_tool_calls_from_response,
)


class TestToolsSchema(unittest.TestCase):
    def test_tool_definition_to_openai_dict(self) -> None:
        tool = ToolDefinition(
            name="edit_file",
            description="Edit a file",
            parameters={"type": "object", "properties": {"path": {"type": "string"}}},
        )
        schema = tool.to_openai_dict()
        self.assertEqual(schema["type"], "function")
        self.assertEqual(schema["function"]["name"], "edit_file")
        self.assertEqual(schema["function"]["description"], "Edit a file")

    def test_tool_call_serialization(self) -> None:
        tc = ToolCall(id="call_1", name="read_file", arguments={"path": "Foo.java"})
        data = tc.to_dict()
        self.assertEqual(data["id"], "call_1")
        self.assertEqual(data["type"], "function")
        self.assertEqual(data["function"]["name"], "read_file")
        self.assertIn('"path": "Foo.java"', data["function"]["arguments"])

    def test_tool_result_to_message(self) -> None:
        tr = ToolResult(call_id="call_1", name="read_file", output="public class Foo {}", success=True)
        msg = tr.to_tool_message()
        self.assertEqual(msg["role"], "tool")
        self.assertEqual(msg["tool_call_id"], "call_1")
        self.assertEqual(msg["content"], "public class Foo {}")

    def test_parse_from_dict_choices(self) -> None:
        raw = {
            "choices": [
                {
                    "message": {
                        "content": "Let me edit the file.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "edit_file",
                                    "arguments": '{"path": "Main.java", "old_str": "a", "new_str": "b"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
        resp = ChatCompletionResponse.from_response(raw)
        self.assertEqual(resp.content, "Let me edit the file.")
        self.assertEqual(resp.finish_reason, "tool_calls")
        self.assertTrue(resp.has_tool_calls)
        self.assertEqual(len(resp.tool_calls), 1)
        tc = resp.tool_calls[0]
        self.assertEqual(tc.id, "call_123")
        self.assertEqual(tc.name, "edit_file")
        self.assertEqual(tc.arguments["path"], "Main.java")

    def test_parse_from_json_string(self) -> None:
        raw_str = '{"name": "run_verification", "arguments": {}}'
        content, tool_calls = parse_tool_calls_from_response(raw_str)
        self.assertEqual(len(tool_calls), 1)
        self.assertEqual(tool_calls[0].name, "run_verification")


if __name__ == "__main__":
    unittest.main()
