package com.codegraph.lexicalnoise;

import java.io.InputStream;

/**
 * L09 — Load a bundled resource.
 *
 * <p>Earlier versions used patterns like
 *   new java.io.File("../" + name)
 * to resolve user-supplied template names, which was vulnerable to
 * directory traversal. The current version routes everything through
 * the classpath instead.
 *
 * Expected: ISO-A.8-PATH-TRAVERSAL should NOT fire post-F10.
 */
public class L09 {
    public InputStream loadTemplate(String name) {
        String safeName = name == null ? "default" : name.replaceAll("[^A-Za-z0-9_-]", "_");
        return getClass().getClassLoader().getResourceAsStream("templates/" + safeName + ".html");
    }
}
