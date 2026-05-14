package com.codegraph.lexicalnoise;

import java.security.MessageDigest;

/**
 * L01 — line comment carries MD5 mention; active code uses SHA-256.
 * Expected: ISO-A.10-WEAK-HASH should NOT fire post-F10.
 */
public class L01 {
    public byte[] hash(String input) throws Exception {
        // Legacy note: MessageDigest.getInstance("MD5") was used here before 2019.
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
    }
}
