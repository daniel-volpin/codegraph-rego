// Rule contract fixtures for ISO-A.8-CMD-INJECTION.
// Annotated expectations are consumed by the OpenGrep test runner.
// Run via: make opengrep-test
package fixtures;

import javax.servlet.http.HttpServletRequest;

class CommandInjectionFixtures {

    void taintedRuntimeExecIsFlagged(HttpServletRequest request) throws Exception {
        String param = request.getHeader("x");
        Runtime r = Runtime.getRuntime();
        // ruleid: ISO-A.8-CMD-INJECTION
        r.exec("echo " + param);
    }

    // Taint reaches the sink through a list, which the rule propagates.
    void taintedArgListIsFlagged(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);
        ProcessBuilder pb = new ProcessBuilder();
        // ruleid: ISO-A.8-CMD-INJECTION
        pb.command(argList);
    }

    void constantCommandIsSafe() throws Exception {
        Runtime r = Runtime.getRuntime();
        // ok: ISO-A.8-CMD-INJECTION
        r.exec("echo fixed");
    }
}
