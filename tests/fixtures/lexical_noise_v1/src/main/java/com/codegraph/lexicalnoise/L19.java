package com.codegraph.lexicalnoise;

/**
 * L19 — char literals 'M', 'D', '5' used as labels in a char array.
 * The multi-char substring "MD5" never appears in active source.
 * Expected: ISO-A.10-WEAK-HASH should NOT fire post-F10.
 */
public class L19 {
    public char[] algorithmCodepoints() {
        return new char[]{ 'M', 'D', '5' };
    }
}
