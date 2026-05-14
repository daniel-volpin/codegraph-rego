package com.codegraph.lexicalnoise;

/**
 * L23 — char literals '?' and '%' used as format-spec markers; no SQL.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L23 {
    public int countPlaceholders(String spec) {
        if (spec == null) {
            return 0;
        }
        int n = 0;
        for (int i = 0; i < spec.length(); i++) {
            char ch = spec.charAt(i);
            if (ch == '?' || ch == '%') {
                n++;
            }
        }
        return n;
    }
}
