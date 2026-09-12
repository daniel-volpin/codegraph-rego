// Rule contract fixtures for ISO-A.8-PATH-TRAVERSAL.
// Annotated expectations are consumed by the OpenGrep test runner.
// Run via: make opengrep-test
package fixtures;

import javax.servlet.http.HttpServletRequest;

class PathTraversalFixtures {

    void taintedPathReachesFile(HttpServletRequest request) throws Exception {
        String param = request.getHeader("x");
        String fileName = "/var/testfiles/" + param;
        // ruleid: ISO-A.8-PATH-TRAVERSAL
        new java.io.FileInputStream(new java.io.File(fileName));
    }

    void taintedPathReachesNioFiles(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        // ruleid: ISO-A.8-PATH-TRAVERSAL
        java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/var/testfiles/" + param));
    }

    void constantPathIsSafe() throws Exception {
        // ok: ISO-A.8-PATH-TRAVERSAL
        new java.io.FileInputStream(new java.io.File("/var/testfiles/fixed.txt"));
    }
}
