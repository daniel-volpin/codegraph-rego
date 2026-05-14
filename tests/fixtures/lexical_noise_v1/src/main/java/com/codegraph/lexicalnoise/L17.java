package com.codegraph.lexicalnoise;

/**
 * L17 — string literal carries ../ token; active code is a pure string check.
 * Expected: ISO-A.8-PATH-TRAVERSAL should NOT fire post-F10.
 */
public class L17 {
    public boolean isSafeRelativePath(String candidate) {
        String message = "Reject any candidate containing the parent-directory token (i.e. ../ or its variants).";
        return candidate != null && !candidate.contains("..") && !message.isEmpty();
    }
}
