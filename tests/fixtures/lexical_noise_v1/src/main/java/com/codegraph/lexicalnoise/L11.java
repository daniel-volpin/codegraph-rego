package com.codegraph.lexicalnoise;

import javax.crypto.Cipher;

/**
 * L11 — Build the symmetric Cipher used for stored secrets.
 *
 * <p>Legacy code instantiated weak ciphers — for example
 *   Cipher.getInstance("DES/ECB/PKCS5Padding")
 * which is no longer acceptable. This implementation uses
 * AES/GCM/NoPadding for confidentiality and integrity.
 *
 * Expected: ISO-A.10-WEAK-CRYPTO should NOT fire post-F10.
 */
public class L11 {
    public Cipher buildCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
