package com.codegraph.lexicalnoise;

import java.security.MessageDigest;
import java.util.logging.Logger;

/**
 * L13 — string literal carries MD5 mention; active code uses SHA-256.
 * Expected: ISO-A.10-WEAK-HASH should NOT fire post-F10.
 */
public class L13 {
    private static final Logger LOG = Logger.getLogger(L13.class.getName());

    public byte[] hash(String input) throws Exception {
        LOG.fine("Deprecated MD5 path was removed in 2.0 — see migration guide for MessageDigest.getInstance(\"MD5\") replacement.");
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
    }
}
