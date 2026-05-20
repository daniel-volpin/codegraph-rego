package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L05 — line comment carries the full XPath-injection FP-triggering
 * pattern (XPathFactory.newInstance + .compile + concat + getParameter);
 * active code returns a static label.
 * Expected: ISO-A.8-XPATH-INJECTION should NOT fire post-F10.
 */
public class L05 {
    public String describe(HttpServletRequest req) {
        // Old impl: XPathFactory.newInstance().newXPath().compile("//user[name='" + req.getParameter("name") + "']").evaluate(doc);
        if (req == null) {
            return "unknown";
        }
        return "compliance-summary";
    }
}
