// Rule contract fixtures for ISO-A.8-LDAP-INJECTION.
// Annotated expectations are consumed by the OpenGrep test runner.
// Run via: make opengrep-test
package fixtures;

import javax.servlet.http.HttpServletRequest;

class LdapInjectionFixtures {

    void taintedFilterReachesSearch(HttpServletRequest request, javax.naming.directory.DirContext ctx)
            throws Exception {
        String param = request.getParameter("x");
        String filter = "(&(objectclass=person)(uid=" + param + "))";
        // ruleid: ISO-A.8-LDAP-INJECTION
        ctx.search("ou=users", filter, new javax.naming.directory.SearchControls());
    }

    void constantFilterIsSafe(javax.naming.directory.DirContext ctx) throws Exception {
        String filter = "(&(objectclass=person)(uid=fixed))";
        // ok: ISO-A.8-LDAP-INJECTION
        ctx.search("ou=users", filter, new javax.naming.directory.SearchControls());
    }
}
