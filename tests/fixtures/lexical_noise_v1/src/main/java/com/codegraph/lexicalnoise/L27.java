package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L27 — text block carries the full XPath-injection FP-triggering
 * pattern (HttpServletRequest + XPathFactory.newInstance + .compile +
 * concat + getParameter); active code returns a static label.
 * Expected: ISO-A.8-XPATH-INJECTION should NOT fire post-F10.
 */
public class L27 {
    private static final String EXAMPLE = """
            Anti-pattern:
              HttpServletRequest req = ...;
              XPathFactory.newInstance().newXPath()
                          .compile("//user[name='" + req.getParameter("name") + "']")
                          .evaluate(doc);
            """;

    public String describe(HttpServletRequest req) {
        if (req == null) {
            return "unknown";
        }
        return EXAMPLE.isEmpty() ? "unset" : "xpath-handling-disabled";
    }
}
