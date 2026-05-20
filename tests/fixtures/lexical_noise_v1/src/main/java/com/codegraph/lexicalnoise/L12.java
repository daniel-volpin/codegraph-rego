package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L12 — Look up a user by request parameter (UNSAFE).
 *
 * <p>This method intentionally illustrates SQL injection: the user
 * parameter is concatenated into the SQL string and executed with
 * Statement.executeQuery — exactly the anti-pattern the linked
 * runbook warns against.
 *
 * Expected: ISO-A.8-SQL-INJECTION SHOULD fire post-F10
 * (verifies F10 preserves the active concatenated executeQuery call).
 */
public class L12 {
    public ResultSet lookup(Connection conn, HttpServletRequest req) throws Exception {
        String userId = req.getParameter("id");
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT name FROM users WHERE id = '" + userId + "'");
    }
}
