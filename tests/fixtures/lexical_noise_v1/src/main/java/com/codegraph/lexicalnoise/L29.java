package com.codegraph.lexicalnoise;

/**
 * L29 — text block carries Runtime.exec and ProcessBuilder examples; active code returns a constant.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L29 {
    private static final String UNSAFE_EXAMPLES = """
            Forbidden patterns:
              Runtime.getRuntime().exec("/bin/sh -c " + userInput)
              new ProcessBuilder("/bin/sh", "-c", userInput).start()
            Use ProcessBuilder with constant argv only.
            """;

    public String policyName() {
        return UNSAFE_EXAMPLES.length() > 0 ? "no-process-execution" : "unset";
    }
}
