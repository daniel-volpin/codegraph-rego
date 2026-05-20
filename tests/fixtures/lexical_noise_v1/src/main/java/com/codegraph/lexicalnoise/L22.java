package com.codegraph.lexicalnoise;

import java.util.ArrayList;
import java.util.List;

/**
 * L22 — char literals ',' and ';' used as CSV delimiters; no SQL execution.
 * Expected: ISO-A.8-SQL-INJECTION should NOT fire post-F10.
 */
public class L22 {
    public List<String> parseFields(String row) {
        List<String> out = new ArrayList<>();
        if (row == null) {
            return out;
        }
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < row.length(); i++) {
            char ch = row.charAt(i);
            if (ch == ',' || ch == ';') {
                out.add(buf.toString());
                buf.setLength(0);
            } else {
                buf.append(ch);
            }
        }
        if (buf.length() > 0) {
            out.add(buf.toString());
        }
        return out;
    }
}
