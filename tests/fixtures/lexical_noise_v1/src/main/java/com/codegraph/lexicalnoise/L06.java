package com.codegraph.lexicalnoise;

import java.security.MessageDigest;

/**
 * L06 — line comment mentions MD5 AND active code calls MessageDigest.getInstance("MD5").
 * Expected: ISO-A.10-WEAK-HASH SHOULD fire post-F10 (verifies F10 preserves active call).
 */
public class L06 {
    public byte[] legacyHash(String input) throws Exception {
        // MD5 retained for backwards compatibility with the v1 hash format.
        return MessageDigest.getInstance("MD5").digest(input.getBytes());
    }
}
