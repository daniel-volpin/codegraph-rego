package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L28 — text block carries the full LDAP-injection FP-triggering pattern
 * (HttpServletRequest + InitialDirContext + .search + concat +
 * getParameter); active code returns a constant.
 * Expected: ISO-A.8-LDAP-INJECTION should NOT fire post-F10.
 */
public class L28 {
    private static final String LDAP_NOTES = """
            Avoid building LDAP filters by concatenation, e.g.
              HttpServletRequest req = ...;
              new InitialDirContext().search(base, "(uid=" + req.getParameter("user") + ")", controls);
            Always escape user input via javax.naming.directory.SearchControls instead.
            """;

    public boolean ldapEnabled(HttpServletRequest req) {
        if (req == null) {
            return false;
        }
        return !LDAP_NOTES.isEmpty() && false;
    }
}
