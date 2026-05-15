package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L02 — line comment carries the full SQL-injection FP-triggering
 * pattern (executeQuery + SELECT + concat + getParameter); active
 * code uses parameter-bound prepareStatement.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L02 {
    public ResultSet lookup(Connection conn, HttpServletRequest req) throws Exception {
        // Earlier code: stmt.executeQuery("SELECT name FROM users WHERE id = '" + req.getParameter("id") + "'");
        String userId = req.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setString(1, userId);
        return ps.executeQuery();
    }
}
