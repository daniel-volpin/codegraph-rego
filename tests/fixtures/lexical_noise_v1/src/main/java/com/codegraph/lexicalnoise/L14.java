package com.codegraph.lexicalnoise;

/**
 * L14 — string literal carries executeQuery; active code performs no SQL.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L14 {
    public String migrationHint() {
        return "Replace Statement.executeQuery(\"...\") with PreparedStatement using placeholders.";
    }
}
