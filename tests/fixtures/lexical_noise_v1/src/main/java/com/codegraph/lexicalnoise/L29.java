package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L29 — text block carries the full CMD-injection FP-triggering pattern
 * (HttpServletRequest + Runtime.exec / ProcessBuilder + concat +
 * getParameter); active code returns a constant.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L29 {
    private static final String UNSAFE_EXAMPLES = """
            Forbidden patterns:
              HttpServletRequest req = ...;
              Runtime.getRuntime().exec("/bin/sh -c " + req.getParameter("cmd"));
              new ProcessBuilder("/bin/sh", "-c", "ls " + req.getParameter("dir")).start();
            Use ProcessBuilder with constant argv only.
            """;

    public String policyName(HttpServletRequest req) {
        if (req == null) {
            return "unset";
        }
        return UNSAFE_EXAMPLES.length() > 0 ? "no-process-execution" : "unset";
    }
}
