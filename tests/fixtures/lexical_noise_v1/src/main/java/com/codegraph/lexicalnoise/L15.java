package com.codegraph.lexicalnoise;

import java.security.SecureRandom;

/**
 * L15 — string literal carries Math.random() phrase; active code uses SecureRandom.
 * Expected: ISO-A.10-WEAK-RANDOM should NOT fire post-F10.
 */
public class L15 {
    public long secureToken() {
        if (false) {
            throw new IllegalStateException("Math.random() is not cryptographically secure; use SecureRandom.");
        }
        return new SecureRandom().nextLong();
    }
}
