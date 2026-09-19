from __future__ import annotations

import re

CALL_ASSIGNMENT_WITH_ARGS_RE = re.compile(
    r"(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>]*\(\)|[A-Za-z_][A-Za-z0-9_$.<>]*)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;]*?)\)\s*;",
    re.DOTALL,
)
METHOD_DECL_RE = re.compile(
    r"(?:public|protected|private)?\s*(?:static\s+)?(?:final\s+)?[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)",
    re.DOTALL,
)
RETURN_RE = re.compile(r"return\s+([^;]+);", re.DOTALL)
MAP_PUT_LITERAL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.put\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', re.DOTALL)
MAP_GET_LITERAL_RE = re.compile(r'(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*"([^"]+)"\s*\)', re.DOTALL)
MAP_PUT_VALUE_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\.put\(\s*"([^"]+)"\s*,\s*([^;]+?)\s*\)\s*;',
    re.DOTALL,
)
MAP_GET_ASSIGNMENT_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*"([^"]+)"\s*\)\s*;',
    re.DOTALL,
)
LIST_ADD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;", re.DOTALL)
LIST_REMOVE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.remove\(\s*(\d+)\s*\)\s*;", re.DOTALL)
LIST_GET_ASSIGNMENT_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*(\d+)\s*\)\s*;",
    re.DOTALL,
)
ARRAY_ASSIGNMENT_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>\[\]]*\[\]\s*)?\{(.*?)\}\s*;",
    re.DOTALL,
)
FILTER_ASSIGNMENT_TEMPLATE = r"\bfilter\w*\s*=\s*[^;]*\b%s\b"
PATH_ASSIGNMENT_TEMPLATE = r"\b(?:file|path|uri)\w*\s*=\s*[^;]*\b%s\b"
PATH_DIRECT_USAGE_TEMPLATE = (
    r"(?:new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;]*\b%s\b"
    r"|Paths\s*\.\s*get\s*\([^;]*\b%s\b"
    r"|new\s+java\.net\.URI\s*\([^;]*\b%s\b)"
)
XPATH_ASSIGNMENT_TEMPLATE = r"\b(?:expr|expression|query|xpath)\w*\s*=\s*[^;]*\b%s\b"
XPATH_USAGE_TEMPLATE = r"(?:\.evaluate\s*\(\s*[^,;)]*\b%s\b|\.compile\s*\(\s*[^;)]*\b%s\b)"
SQL_ASSIGNMENT_TEMPLATE = r"\bsql\w*\s*=\s*[^;]*\b%s\b"
SQL_USAGE_TEMPLATE = (
    r"(?:prepareStatement\s*\(\s*[^,;)]*\b%s\b"
    r"|prepareCall\s*\(\s*[^,;)]*\b%s\b"
    r"|execute(?:Query|Update)?\s*\(\s*[^,;)]*\b%s\b"
    r"|JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|update|batchUpdate)\s*\(\s*[^,;)]*\b%s\b)"
)
COMMAND_ASSIGNMENT_TEMPLATE = r"\b(?:cmd|command)\w*\s*=\s*[^;]*\b%s\b"
COMMAND_USAGE_TEMPLATE = (
    r"(?:\.exec\s*\(\s*[^,;)]*\b%s\b|\.command\s*\([^;)]*\b%s\b|new\s+ProcessBuilder\s*\([^;)]*\b%s\b)"
)
COMMAND_LIST_USAGE_RE = re.compile(
    r"(?:new\s+ProcessBuilder\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|\.command\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))",
    re.IGNORECASE,
)
COMMAND_EXEC_FIRST_ARG_VAR_RE = re.compile(r"\.exec\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE)
COMMAND_EXEC_ENV_ARG_VAR_RE = re.compile(
    r"\.exec\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))",
    re.IGNORECASE,
)
STRING_LITERAL_FULL_RE = re.compile(r'^"([^"\\]*(?:\\.[^"\\]*)*)"$', re.DOTALL)
