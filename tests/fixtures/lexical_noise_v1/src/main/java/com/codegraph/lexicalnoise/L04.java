package com.codegraph.lexicalnoise;

/**
 * L04 — line comment carries ProcessBuilder/.exec( mentions; no process execution in active code.
 * Expected: ISO-A.8-CMD-INJECTION should NOT fire post-F10.
 */
public class L04 {
    public String label(String topic) {
        // Earlier prototypes spawned a ProcessBuilder here; replaced with a constant table below.
        // Reference: Runtime.getRuntime().exec( ... ) approach proved unsafe.
        return topic == null ? "unknown" : topic.trim();
    }
}
