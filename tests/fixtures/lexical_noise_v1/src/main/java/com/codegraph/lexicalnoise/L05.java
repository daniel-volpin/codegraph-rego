package com.codegraph.lexicalnoise;

/**
 * L05 — line comment carries XPathFactory.newInstance( token; active code returns a constant.
 * Expected: ISO-A.8-XPATH-INJECTION should NOT fire post-F10.
 */
public class L05 {
    public String describe() {
        // The old impl used XPathFactory.newInstance( ).newXPath().compile(expr).evaluate(doc).
        // We now serve a static label instead.
        return "compliance-summary";
    }
}
