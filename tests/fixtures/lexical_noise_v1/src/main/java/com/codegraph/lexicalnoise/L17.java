package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L17 — string literal carries the full PATH-traversal FP-triggering
 * pattern (HttpServletRequest + new java.io.File + concat + ../ +
 * getParameter); active code is a pure string check.
 * Expected: ISO-A.8-PATH-TRAVERSAL should NOT fire post-F10.
 */
public class L17 {
    public boolean isSafeRelativePath(HttpServletRequest req, String candidate) {
        if (req == null) {
            return false;
        }
        String message = "Reject any HttpServletRequest input that produces new java.io.File(\"../\" + req.getParameter(\"file\")) or similar parent-directory escapes.";
        return candidate != null && !candidate.contains("..") && !message.isEmpty();
    }
}
