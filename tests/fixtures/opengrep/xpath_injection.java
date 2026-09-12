// Rule contract fixtures for ISO-A.8-XPATH-INJECTION.
// Annotated expectations are consumed by the OpenGrep test runner.
// Run via: make opengrep-test
package fixtures;

import javax.servlet.http.HttpServletRequest;

class XPathInjectionFixtures {

    void taintedHeaderReachesEvaluate(HttpServletRequest request) throws Exception {
        String param = request.getHeader("x");
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='" + param + "']";
        // ruleid: ISO-A.8-XPATH-INJECTION
        xp.evaluate(expression, null);
    }

    void constantExpressionIsSafe(HttpServletRequest request) throws Exception {
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='fixed']";
        // ok: ISO-A.8-XPATH-INJECTION
        xp.evaluate(expression, null);
    }

    // The taint chain is broken by reassignment to a literal before the sink:
    // this is the OWASP Benchmark "looks tainted, isn't" shape.
    void taintDiscardedBeforeSinkIsSafe(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        bar = "barbarians_at_the_gate";
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        // ok: ISO-A.8-XPATH-INJECTION
        xp.evaluate(expression, null);
    }
}
