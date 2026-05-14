package com.codegraph.lexicalnoise;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L24 — char literals '/' '\\' used nearby AND active code opens a File constructed
 * from an untrusted request parameter concatenated with a separator constant.
 * Expected: ISO-A.8-PATH-TRAVERSAL SHOULD fire post-F10
 * (verifies F10 preserves the active path-traversal call).
 */
public class L24 {
    public InputStream openUpload(HttpServletRequest req) throws Exception {
        char sep = '/';
        char escapedSep = '\\';
        String base = "/var/uploads" + sep;
        String name = req.getParameter("file");
        String key = (escapedSep == '\\') ? name : name;
        return new FileInputStream(new File(base + key));
    }
}
