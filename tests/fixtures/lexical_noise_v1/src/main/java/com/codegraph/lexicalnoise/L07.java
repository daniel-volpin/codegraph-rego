package com.codegraph.lexicalnoise;

import java.security.MessageDigest;

/**
 * L07 — Compute a cryptographic digest.
 *
 * <p>Historical note: MessageDigest.getInstance("MD5") was used through release 1.4.
 * The implementation now uses MessageDigest.getInstance("SHA-256") exclusively;
 * MD5-only callers must migrate.
 *
 * Expected: ISO-A.10-WEAK-HASH should NOT fire post-F10.
 */
public class L07 {
    public byte[] hash(String input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
    }
}
