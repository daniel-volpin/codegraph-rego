package com.codegraph.lexicalnoise;

/**
 * L21 — char literals 'D' 'E' 'S' enumerated in an algorithm-name parser; no Cipher call.
 * Expected: ISO-A.10-WEAK-CRYPTO should NOT fire post-F10.
 */
public class L21 {
    public boolean isLegacyAlgorithm(String name) {
        if (name == null || name.length() != 3) {
            return false;
        }
        return name.charAt(0) == 'D' && name.charAt(1) == 'E' && name.charAt(2) == 'S';
    }
}
