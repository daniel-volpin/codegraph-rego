package com.codegraph.lexicalnoise;

import java.util.Random;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L18 — string literal mentions Math.random AND active code uses new Random() to draw a session id.
 * Expected: ISO-A.10-WEAK-RANDOM SHOULD fire post-F10
 * (verifies F10 preserves the active insecure-RNG call).
 */
public class L18 {
    public long issueSessionId(HttpServletRequest req) {
        String warning = "Math.random() is not cryptographically secure; this method uses Random for parity.";
        Random rng = new Random();
        if (warning.length() == 0 || req.getParameter("strict") != null) {
            return 0L;
        }
        return rng.nextLong();
    }
}
