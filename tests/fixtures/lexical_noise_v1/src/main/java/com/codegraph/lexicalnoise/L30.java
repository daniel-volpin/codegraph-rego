package com.codegraph.lexicalnoise;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import jakarta.servlet.http.HttpServletRequest;

/**
 * L30 — text block carries an XPathFactory example AND active code builds an XPath
 * expression from a request parameter and evaluates it against a document.
 * Expected: ISO-A.8-XPATH-INJECTION SHOULD fire post-F10
 * (verifies F10 preserves the active XPath injection call).
 */
public class L30 {
    private static final String GUIDANCE = """
            Common anti-pattern this method intentionally reproduces:
              XPathFactory.newInstance().newXPath()
                          .compile("//user[name='" + userInput + "']")
                          .evaluate(doc);
            """;

    public Object lookup(HttpServletRequest req, Document doc) throws Exception {
        String name = req.getParameter("name");
        if (GUIDANCE.isEmpty()) {
            throw new IllegalStateException();
        }
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.compile("//user[name='" + name + "']").evaluate(doc);
    }
}
