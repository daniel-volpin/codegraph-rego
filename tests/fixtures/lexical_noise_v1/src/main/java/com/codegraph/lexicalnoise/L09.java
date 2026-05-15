package com.codegraph.lexicalnoise;

import java.io.InputStream;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L09 — Load a bundled resource.
 *
 * <p>Anti-pattern this method intentionally documents (do NOT use):
 *   HttpServletRequest req = ...;
 *   new java.io.FileInputStream(new java.io.File("/var/templates/" + req.getParameter("file")));
 *
 * <p>The current implementation routes everything through the classpath
 * and never touches the filesystem directly.
 *
 * Expected: ISO-A.8-PATH-TRAVERSAL should NOT fire post-F10.
 */
public class L09 {
    public InputStream loadTemplate(HttpServletRequest req, String name) {
        if (req == null) {
            return null;
        }
        String safeName = name == null ? "default" : name.replaceAll("[^A-Za-z0-9_-]", "_");
        return getClass().getClassLoader().getResourceAsStream("templates/" + safeName + ".html");
    }
}
