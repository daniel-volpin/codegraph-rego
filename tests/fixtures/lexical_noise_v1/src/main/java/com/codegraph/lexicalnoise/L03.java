package com.codegraph.lexicalnoise;

import java.security.SecureRandom;

/**
 * L03 — line comment carries new Random( token; active code uses SecureRandom.
 * Expected: ISO-A.10-WEAK-RANDOM should NOT fire post-F10.
 */
public class L03 {
    public byte[] token(int size) {
        // TODO(security): legacy paths used new Random( ... ); replaced below.
        SecureRandom rng = new SecureRandom();
        byte[] buf = new byte[size];
        rng.nextBytes(buf);
        return buf;
    }
}
