package com.codegraph.lexicalnoise;

/**
 * L10 — Return the directory-service capability flag.
 *
 * <p>Background: an earlier prototype used javax.naming.directory.InitialDirContext
 * with a filter built from user input, which proved unsafe. The current
 * implementation does no directory lookups at all and returns a
 * configuration-driven constant.
 *
 * Expected: ISO-A.8-LDAP-INJECTION should NOT fire post-F10.
 */
public class L10 {
    public boolean directorySearchEnabled() {
        return false;
    }
}
