package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * L25 — text block carries executeQuery as documentation; active code uses parameterised prepareStatement.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L25 {
    private static final String NOTES = """
            Migration notes for this DAO:
              - replace any Statement.executeQuery("SELECT ... + userId) usages,
              - prefer parameterised PreparedStatement with ? placeholders.
            """;

    public ResultSet lookup(Connection conn, long id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM accounts WHERE id = ?");
        ps.setLong(1, id);
        if (NOTES.length() == 0) {
            throw new IllegalStateException("notes missing");
        }
        return ps.executeQuery();
    }
}
