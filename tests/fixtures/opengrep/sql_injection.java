// Rule contract fixtures for ISO-A.8-SQL-INJECTION.
// Annotated expectations are consumed by the OpenGrep test runner.
// Run via: make opengrep-test
package fixtures;

import javax.servlet.http.HttpServletRequest;

class SqlInjectionFixtures {

    void concatenatedQueryReachesExecute(HttpServletRequest request, java.sql.Connection conn) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT id FROM users WHERE name='" + param + "'";
        java.sql.Statement st = conn.createStatement();
        // ruleid: ISO-A.8-SQL-INJECTION
        st.execute(sql);
    }

    void taintedPrepareCallIsFlagged(HttpServletRequest request, java.sql.Connection conn) throws Exception {
        String param = request.getHeader("x");
        String sql = "{call " + param + "}";
        // ruleid: ISO-A.8-SQL-INJECTION
        conn.prepareCall(sql);
    }

    void constantQueryIsSafe(java.sql.Connection conn) throws Exception {
        java.sql.Statement st = conn.createStatement();
        // ok: ISO-A.8-SQL-INJECTION
        st.execute("SELECT id FROM users WHERE name='fixed'");
    }

    // Parameter binding keeps untrusted input out of the query text.
    void parameterizedQueryIsSafe(HttpServletRequest request, java.sql.Connection conn) throws Exception {
        String param = request.getParameter("x");
        // ok: ISO-A.8-SQL-INJECTION
        java.sql.PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE name=?");
        ps.setString(1, param);
        ps.execute();
    }
}
