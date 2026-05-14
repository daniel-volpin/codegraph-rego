package com.codegraph.lexicalnoise;

/**
 * L27 — text block carries XPathFactory and .evaluate( as documentation; active code returns a constant.
 * Expected: ISO-A.8-XPATH-INJECTION should NOT fire post-F10.
 */
public class L27 {
    private static final String EXAMPLE = """
            Anti-pattern:
              XPathFactory.newInstance().newXPath()
                          .compile("//user[name='" + name + "']")
                          .evaluate(doc);
            """;

    public String describe() {
        return EXAMPLE.isEmpty() ? "unset" : "xpath-handling-disabled";
    }
}
