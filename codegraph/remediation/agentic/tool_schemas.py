"""JSON schemas for OpenAI-compatible function tool definitions for the remediation agent."""

from __future__ import annotations

AGENT_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a source or configuration file in the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the file from the workspace root (e.g. src/main/java/com/acme/Service.java).",
                    }
                },
                "required": ["relative_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": "Replace an exact block of text in a file with updated code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the file to edit.",
                    },
                    "old_str": {
                        "type": "string",
                        "description": "Exact consecutive lines to replace.",
                    },
                    "new_str": {
                        "type": "string",
                        "description": "The new replacement code.",
                    },
                },
                "required": ["relative_path", "old_str", "new_str"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_import",
            "description": "Add an import statement to a Java file cleanly below package declaration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the Java file.",
                    },
                    "import_statement": {
                        "type": "string",
                        "description": "Full import statement (e.g. 'import java.sql.PreparedStatement;' or 'java.sql.PreparedStatement').",
                    },
                },
                "required": ["relative_path", "import_statement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_files",
            "description": "Find files in the workspace matching a glob pattern (e.g. '**/*.java', 'pom.xml', '**/*Repository.java').",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (default: '**/*').",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search for text or regex patterns across files in the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex or substring pattern to search for.",
                    }
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_graph_context",
            "description": "Query the Neo4j knowledge graph for callers, callees, and field declarations of a method or type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "Name or signature of the method/type to query (e.g. 'getUserName' or 'SqlDemo').",
                    }
                },
                "required": ["symbol_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_verification",
            "description": "Trigger the 3-gate verification pipeline on the current workspace: compilation, regression tests, and OPA policy evaluation.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish_remediation",
            "description": "Complete remediation and propose the candidate patch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Summary explanation of the changes made and why they are secure and semantically sound.",
                    }
                },
                "required": ["reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refuse_remediation",
            "description": "Refuse to change code, either because the finding is already safe (likely false positive) or because a safe fix needs a human design decision.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Detailed explanation of why safe automated remediation is impossible (e.g. missing path policy, breaking external API).",
                    }
                },
                "required": ["reason"],
            },
        },
    },
]
