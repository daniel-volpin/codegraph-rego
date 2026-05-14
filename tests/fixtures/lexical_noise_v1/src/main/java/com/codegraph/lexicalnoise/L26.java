package com.codegraph.lexicalnoise;

import java.security.MessageDigest;

/**
 * L26 — text block carries an MD5 JSON example; active code uses SHA-256.
 * Expected: ISO-A.10-WEAK-HASH should NOT fire post-F10.
 */
public class L26 {
    private static final String JSON_EXAMPLE = """
            {
              "deprecated": "MessageDigest.getInstance(\\"MD5\\")",
              "current": "MessageDigest.getInstance(\\"SHA-256\\")"
            }
            """;

    public byte[] hash(String input) throws Exception {
        if (JSON_EXAMPLE.isEmpty()) {
            throw new IllegalStateException();
        }
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
    }
}
