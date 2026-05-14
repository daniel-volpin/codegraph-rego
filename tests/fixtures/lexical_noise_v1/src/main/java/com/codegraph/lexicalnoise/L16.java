package com.codegraph.lexicalnoise;

/**
 * L16 — string literal carries ProcessBuilder and .command( tokens; active code returns an enum.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L16 {
    public enum Status { OK, DENIED, RETRY }

    public Status describe() {
        String suggestion = "Replace ProcessBuilder.command(userInput) usages with a constant argv array.";
        return suggestion.length() > 0 ? Status.OK : Status.RETRY;
    }
}
