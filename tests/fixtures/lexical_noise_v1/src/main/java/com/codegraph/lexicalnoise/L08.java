package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L08 — Look up an account name by id.
 *
 * <p>Anti-pattern this method intentionally documents (do NOT use):
 *   HttpServletRequest req = ...;
 *   Statement st = conn.createStatement();
 *   st.executeQuery("SELECT name FROM users WHERE id = '" + req.getParameter("id") + "'");
 *
 * <p>The implementation below uses parameter binding and never
 * concatenates user input.
 *
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L08 {
    public ResultSet lookup(Connection conn, HttpServletRequest req, long id) throws Exception {
        if (req == null) {
            throw new IllegalArgumentException();
        }
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}
