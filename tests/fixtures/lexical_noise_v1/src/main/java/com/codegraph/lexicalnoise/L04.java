package com.codegraph.lexicalnoise;

import jakarta.servlet.http.HttpServletRequest;

/**
 * L04 — line comment carries the full CMD-injection FP-triggering
 * pattern (ProcessBuilder + .command + concat + getParameter +
 * HttpServletRequest reference); active code does no process work.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L04 {
    public String label(HttpServletRequest req, String topic) {
        // Earlier (unsafe): new ProcessBuilder().command("/bin/sh", "-c", "ls " + req.getParameter("dir")).start();
        // Reference removed: Runtime.getRuntime().exec("ping -c 1 " + req.getParameter("host"));
        if (req == null) {
            return "unknown";
        }
        return topic == null ? "unknown" : topic.trim();
    }
}
