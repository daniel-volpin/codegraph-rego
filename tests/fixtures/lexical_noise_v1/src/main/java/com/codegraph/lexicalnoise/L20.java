package com.codegraph.lexicalnoise;

/**
 * L20 — char literals '/' and '\\' used as path-separator constants; no file IO performed.
 * Expected: ISO-A.8-PATH-TRAVERSAL should NOT fire post-F10.
 */
public class L20 {
    public String normalizeSeparators(String path) {
        if (path == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(path.length());
        for (int i = 0; i < path.length(); i++) {
            char ch = path.charAt(i);
            out.append(ch == '\\' ? '/' : ch);
        }
        return out.toString();
    }
}
