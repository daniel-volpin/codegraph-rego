from __future__ import annotations

import re

UNTRUSTED_INPUT_PATTERNS = (
    re.compile(r"getParameter\s*\(", re.IGNORECASE),
    re.compile(r"getHeader\s*\(", re.IGNORECASE),
    re.compile(r"getQueryString\s*\(", re.IGNORECASE),
    re.compile(r"getCookies\s*\(", re.IGNORECASE),
)
EXTENDED_UNTRUSTED_INPUT_PATTERNS = (
    *UNTRUSTED_INPUT_PATTERNS,
    re.compile(r"getParameterMap\s*\(", re.IGNORECASE),
    re.compile(r"getParameterValues\s*\(", re.IGNORECASE),
    re.compile(r"getParameterNames\s*\(", re.IGNORECASE),
    re.compile(r"getHeaders\s*\(", re.IGNORECASE),
    re.compile(r"getTheParameter\s*\(", re.IGNORECASE),
    re.compile(r"\b\w*cookie\w*\.getValue\s*\(", re.IGNORECASE),
)
SQL_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
PATH_LDAP_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
COMMAND_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(", re.IGNORECASE),
    re.compile(r"Files\s*\.\s*newInputStream\s*\(", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(", re.IGNORECASE),
)
PATH_DYNAMIC_CONSTRUCTION_PATTERNS = (
    re.compile(r"\b(?:file|path|uri)\w*\s*=\s*[^;\n]*\+", re.IGNORECASE),
    re.compile(
        r"new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;\n]*\+",
        re.IGNORECASE,
    ),
    re.compile(r"new\s+java\.net\.URI\s*\([^;\n]*\+", re.IGNORECASE),
)
PATH_DYNAMIC_ARGUMENT_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.File\s*\(\s*[^,]+,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
)
PATH_SINK_VARIABLE_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.File\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
)
DIRECT_PATH_UNTRUSTED_PATTERNS = (
    re.compile(
        r"new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"new\s+java\.io\.File\s*\(\s*[^,]+,\s*[^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(r"Paths\s*\.\s*get\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(", re.IGNORECASE),
    re.compile(
        r"\b(?:file|path|uri)\w*\s*=\s*[^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(", re.IGNORECASE
    ),
)
PATH_SAFE_RESOURCE_PATTERNS = (
    re.compile(r"Utils\s*\.\s*getFileFromClasspath\s*\(", re.IGNORECASE),
    re.compile(r"getClass\s*\(\s*\)\s*\.\s*getClassLoader\s*\(\s*\)", re.IGNORECASE),
    re.compile(r"\.getResourceAsStream\s*\(", re.IGNORECASE),
    re.compile(r"\.getResource\s*\(", re.IGNORECASE),
)
CMDI_PATTERNS = (
    re.compile(r"\.exec\s*\(", re.IGNORECASE),
    re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE),
    re.compile(r"\.command\s*\(", re.IGNORECASE),
)
COMMAND_LIST_ADD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;", re.DOTALL)
COMMAND_ARRAY_ASSIGNMENT_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>\[\]]*\[\]\s*)?\{(.*?)\}\s*;",
    re.DOTALL,
)
COMMAND_APPEND_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.append\(\s*([^;]+?)\s*\)\s*;", re.DOTALL)
COMMAND_EXEC_MULTI_ARG_RE = re.compile(
    r"\.exec\s*\(\s*(?P<first>[^,]+?)\s*,\s*(?P<second>[A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[^)]*)?\)",
    re.DOTALL | re.IGNORECASE,
)
COMMAND_EXEC_SINGLE_ARG_RE = re.compile(
    r"\.exec\s*\(\s*(?P<first>(?:[^()]|\([^)]*\))+?)\s*\)",
    re.DOTALL | re.IGNORECASE,
)
COMMAND_LIST_USAGE_RE = re.compile(
    r"(?:new\s+ProcessBuilder\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|\.command\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))",
    re.IGNORECASE,
)
COMMAND_EXPR_USAGE_RE = re.compile(
    r"(?:new\s+ProcessBuilder\s*\(\s*(?P<ctor>[^)]*?)\s*\)|\.command\s*\(\s*(?P<call>[^)]*?)\s*\))",
    re.DOTALL | re.IGNORECASE,
)
BUILDER_TOSTRING_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.toString\s*\(\s*\)", re.IGNORECASE)
LDAP_PATTERNS = (
    re.compile(r"InitialDirContext", re.IGNORECASE),
    re.compile(r"DirContext", re.IGNORECASE),
    re.compile(r"\.search\s*\(", re.IGNORECASE),
)
LDAP_FILTER_VARIABLE_PATTERNS = (
    re.compile(
        r"\.search\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))",
        re.IGNORECASE,
    ),
)
DIRECT_LDAP_UNTRUSTED_PATTERNS = (
    re.compile(
        r"\.search\s*\(\s*[^,]+,\s*[^;\n]*(?:getParameter|getHeader|getQueryString|getCookies|getTheParameter)\s*\(",
        re.IGNORECASE,
    ),
)
XPATH_PATTERNS = (
    re.compile(r"XPathFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
    re.compile(r"\.evaluate\s*\(", re.IGNORECASE),
)
XPATH_SINK_VARIABLE_PATTERNS = (
    re.compile(r"\.evaluate\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"\.compile\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", re.IGNORECASE),
)
DIRECT_XPATH_UNTRUSTED_PATTERNS = (
    re.compile(
        r"\.(?:evaluate|compile)\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
)
SQL_PREPARE_CALL_RE = re.compile(r"prepareCall\s*\(", re.IGNORECASE)
SQL_PREPARE_STATEMENT_RE = re.compile(r"prepareStatement\s*\(", re.IGNORECASE)
SQL_CALLABLE_STATEMENT_RE = re.compile(r"CallableStatement", re.IGNORECASE)
SQL_EXECUTE_CALL_PATTERNS = (
    re.compile(r"\.executeQuery\s*\(", re.IGNORECASE),
    re.compile(r"\.executeUpdate\s*\(", re.IGNORECASE),
    re.compile(r"\.execute\s*\(", re.IGNORECASE),
    re.compile(r"\.addBatch\s*\(", re.IGNORECASE),
    re.compile(
        r"JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|queryForLong|update|batchUpdate)\s*\(",
        re.IGNORECASE,
    ),
)
SQL_SINK_VARIABLE_PATTERNS = (
    re.compile(
        r"(?:prepareStatement|prepareCall|executeQuery|executeUpdate|execute|addBatch)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))",
        re.IGNORECASE,
    ),
    re.compile(
        r"JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|queryForLong|update|batchUpdate)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))",
        re.IGNORECASE,
    ),
)
SQL_SINK_TOSTRING_VARIABLE_PATTERNS = (
    re.compile(
        r"(?:prepareStatement|prepareCall|executeQuery|executeUpdate|execute|addBatch)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\.toString\s*\(\s*\)\s*(?:,|\))",
        re.IGNORECASE,
    ),
    re.compile(
        r"JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|queryForLong|update|batchUpdate)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\.toString\s*\(\s*\)\s*(?:,|\))",
        re.IGNORECASE,
    ),
)
DIRECT_SQL_UNTRUSTED_PATTERNS = (
    re.compile(
        r"(?:prepareStatement|prepareCall|executeQuery|executeUpdate|execute)\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|update|batchUpdate)\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
)
STRING_BUILDER_RE = re.compile(r"String(?:Builder|Buffer)", re.IGNORECASE)
APPEND_CALL_RE = re.compile(r"\.append\s*\(", re.IGNORECASE)
STRING_CONCAT_PATTERNS = (
    re.compile(r'"[^"\n]*"\s*\+\s*[A-Za-z_(]', re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*\"[^\n]*\"", re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*[A-Za-z_][A-Za-z0-9_.(]*", re.IGNORECASE),
)
