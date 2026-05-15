package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L10 — Return the directory-service capability flag.
 *
 * <p>Anti-pattern this method intentionally documents (do NOT use):
 *   HttpServletRequest req = ...;
 *   new javax.naming.directory.InitialDirContext().search(base, "(uid=" + req.getParameter("user") + ")", controls);
 *
 * <p>The current implementation does no directory lookups at all and
 * returns a configuration-driven constant.
 *
 * Expected: ISO-A.8-LDAP-INJECTION should NOT fire post-F10.
 */
public class L10 {
    public boolean directorySearchEnabled(HttpServletRequest req) {
        if (req == null) {
            return false;
        }
        return false;
    }
}
