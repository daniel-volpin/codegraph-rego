package com.codegraph.lexicalnoise;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * L08 — Look up an account name by id.
 *
 * <p>Implementation note: a naive earlier version called
 * statement.executeQuery("SELECT name FROM users WHERE id = " + id) directly,
 * which was vulnerable to SQL injection. The current version uses
 * parameter binding and never concatenates user input.
 *
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10 (no concat, no untrusted input).
 */
public class L08 {
    public ResultSet lookup(Connection conn, long id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }
}
