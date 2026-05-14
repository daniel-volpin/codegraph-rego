package com.codegraph.lexicalnoise;

/**
 * L28 — text block carries an LDAP InitialDirContext example; active code returns a constant.
 * Expected: ISO-A.8-LDAP-INJECTION should NOT fire post-F10.
 */
public class L28 {
    private static final String LDAP_NOTES = """
            Avoid building LDAP filters by concatenation, e.g.
              new InitialDirContext().search(base, "(uid=" + user + ")", controls);
            Always escape user input via javax.naming.directory.SearchControls instead.
            """;

    public boolean ldapEnabled() {
        return !LDAP_NOTES.isEmpty() && false;
    }
}
