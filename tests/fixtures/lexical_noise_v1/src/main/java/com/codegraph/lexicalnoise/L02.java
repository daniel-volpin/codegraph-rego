package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L02 — line comment carries executeQuery; active code uses parameterised prepareStatement.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L02 {
    public ResultSet lookup(Connection conn, HttpServletRequest req) throws Exception {
        String userId = req.getParameter("id");
        // Earlier revisions used Statement.executeQuery directly; replaced with prepared statement below.
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setString(1, userId);
        return ps.executeQuery();
    }
}
