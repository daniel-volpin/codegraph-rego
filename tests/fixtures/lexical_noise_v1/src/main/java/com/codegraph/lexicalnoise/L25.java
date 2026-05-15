package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L25 — text block carries the full SQL-injection FP-triggering pattern
 * (HttpServletRequest + executeQuery + SELECT + concat + getParameter);
 * active code uses parameter-bound prepareStatement.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L25 {
    private static final String NOTES = """
            HttpServletRequest req = ...;
            Statement st = conn.createStatement();
            st.executeQuery("SELECT name FROM accounts WHERE id = '" + req.getParameter("id") + "'");
            """;

    public ResultSet lookup(Connection conn, long id) throws Exception {
        if (NOTES.isEmpty()) {
            throw new IllegalStateException();
        }
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM accounts WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}
