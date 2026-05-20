package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L14 — string literal carries the full SQL-injection FP-triggering
 * pattern (HttpServletRequest + executeQuery + SELECT + concat +
 * getParameter); active code performs no SQL.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L14 {
    public String migrationHint(HttpServletRequest req) {
        if (req == null) {
            return "unknown";
        }
        return "Replace HttpServletRequest-driven Statement.executeQuery(\"SELECT * FROM t WHERE id = \" + req.getParameter(\"id\")) with parameterised PreparedStatement.";
    }
}
