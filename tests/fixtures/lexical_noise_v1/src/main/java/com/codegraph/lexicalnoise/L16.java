package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L16 — string literal carries the full CMD-injection FP-triggering
 * pattern (HttpServletRequest + ProcessBuilder + .command + concat +
 * getParameter); active code returns an enum.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L16 {
    public enum Status { OK, DENIED, RETRY }

    public Status describe(HttpServletRequest req) {
        if (req == null) {
            return Status.RETRY;
        }
        String suggestion = "Replace new ProcessBuilder().command(\"sh\", \"-c\", \"ls \" + req.getParameter(\"dir\")).start() with constant argv arrays only — HttpServletRequest input must never reach Runtime.getRuntime().exec.";
        return suggestion.length() > 0 ? Status.OK : Status.RETRY;
    }
}
