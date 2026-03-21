"""Tests for the graph-aware multi-hop taint path finder."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codegraph.policy.taint_graph import TaintPathFinder


def _write_java(tmp: str, name: str, body: str) -> str:
    """Write a minimal Java file and return its absolute path."""
    path = Path(tmp) / name
    path.write_text(f"public class Fake {{\n{body}\n}}\n", encoding="utf-8")
    return path.as_posix()


def _snapshot(sig: str, file_path: str, calls: list[str] | None = None) -> dict:
    return {
        "signature": sig,
        "file_path": file_path,
        "start_line": 2,
        "end_line": 3,
        "calls": calls or [],
    }


class TestTaintPathFinderEmpty(unittest.TestCase):
    def test_no_callees_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fp = _write_java(tmp, "A.java", "  String x = request.getParameter(\"p\");")
            index = {"a.A.doGet()": _snapshot("a.A.doGet()", fp)}
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("a.A.doGet()")
            self.assertEqual(result, [])

    def test_unknown_signature_returns_empty(self) -> None:
        finder = TaintPathFinder({})
        result = finder.find_reachable_sinks("nonexistent.Method()")
        self.assertEqual(result, [])


class TestTaintPathFinderSQLOnehop(unittest.TestCase):
    """Direct callee contains a SQL execute call → SQL sink found at hops=1."""

    def test_sql_sink_at_depth_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller_fp = _write_java(
                tmp,
                "Controller.java",
                '  String p = request.getParameter("x");\n  helper(p);',
            )
            helper_fp = _write_java(
                tmp,
                "Helper.java",
                "  stmt.executeQuery(sql);",
            )
            index = {
                "pkg.Controller.doPost()": _snapshot(
                    "pkg.Controller.doPost()",
                    controller_fp,
                    calls=["pkg.Helper.run()"],
                ),
                "pkg.Helper.run()": _snapshot("pkg.Helper.run()", helper_fp),
            }
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("pkg.Controller.doPost()")
            sink_types = {r["sink_type"] for r in result}
            self.assertIn("sql", sink_types)
            sql_entry = next(r for r in result if r["sink_type"] == "sql")
            self.assertEqual(sql_entry["hops"], 1)

    def test_sql_sink_not_in_root_method_source(self) -> None:
        """Root method with executeQuery should NOT appear in taint_paths at hops=0."""
        with tempfile.TemporaryDirectory() as tmp:
            fp = _write_java(
                tmp,
                "Direct.java",
                '  String p = request.getParameter("x");\n  stmt.executeQuery(p);',
            )
            index = {"pkg.Direct.doGet()": _snapshot("pkg.Direct.doGet()", fp)}
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("pkg.Direct.doGet()")
            # Root method is depth 0 – TaintPathFinder only checks depth >= 1.
            self.assertEqual(result, [])


class TestTaintPathFinderMultiHop(unittest.TestCase):
    """Two-hop chain: Controller → Intermediate → SqlSink."""

    def test_sql_sink_at_depth_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl_fp = _write_java(tmp, "Ctrl.java", "  helper(request.getParameter(\"x\"));")
            mid_fp = _write_java(tmp, "Mid.java", "  sink(val);")
            sink_fp = _write_java(tmp, "Sink.java", "  stmt.executeQuery(sql);")
            index = {
                "pkg.Ctrl.doPost()": _snapshot(
                    "pkg.Ctrl.doPost()", ctrl_fp, calls=["pkg.Mid.process()"]
                ),
                "pkg.Mid.process()": _snapshot(
                    "pkg.Mid.process()", mid_fp, calls=["pkg.Sink.run()"]
                ),
                "pkg.Sink.run()": _snapshot("pkg.Sink.run()", sink_fp),
            }
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("pkg.Ctrl.doPost()")
            sink_types = {r["sink_type"] for r in result}
            self.assertIn("sql", sink_types)
            sql_entry = next(r for r in result if r["sink_type"] == "sql")
            self.assertEqual(sql_entry["hops"], 2)

    def test_max_depth_limits_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a_fp = _write_java(tmp, "A.java", "  b();")
            b_fp = _write_java(tmp, "B.java", "  c();")
            c_fp = _write_java(tmp, "C.java", "  stmt.executeQuery(sql);")
            index = {
                "pkg.A.m()": _snapshot("pkg.A.m()", a_fp, calls=["pkg.B.m()"]),
                "pkg.B.m()": _snapshot("pkg.B.m()", b_fp, calls=["pkg.C.m()"]),
                "pkg.C.m()": _snapshot("pkg.C.m()", c_fp),
            }
            finder = TaintPathFinder(index)
            # depth=2 means hops 1..2; C is at hop 2 and will be visited (max_depth is inclusive)
            result = finder.find_reachable_sinks("pkg.A.m()", max_depth=2)
            sink_types = {r["sink_type"] for r in result}
            self.assertIn("sql", sink_types)

            # depth=1 means only direct callees checked; C is at hop 2 → not found
            result_shallow = finder.find_reachable_sinks("pkg.A.m()", max_depth=1)
            self.assertNotIn("sql", {r["sink_type"] for r in result_shallow})


class TestTaintPathFinderMultipleSinks(unittest.TestCase):
    """A chain that reaches both SQL and command sinks."""

    def test_multiple_sink_types_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl_fp = _write_java(tmp, "Ctrl.java", "  helperA(p); helperB(p);")
            sql_fp = _write_java(tmp, "SqlH.java", "  stmt.executeQuery(sql);")
            cmd_fp = _write_java(tmp, "CmdH.java", "  Runtime.getRuntime().exec(cmd);")
            index = {
                "pkg.Ctrl.doPost()": _snapshot(
                    "pkg.Ctrl.doPost()",
                    ctrl_fp,
                    calls=["pkg.SqlH.run()", "pkg.CmdH.run()"],
                ),
                "pkg.SqlH.run()": _snapshot("pkg.SqlH.run()", sql_fp),
                "pkg.CmdH.run()": _snapshot("pkg.CmdH.run()", cmd_fp),
            }
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("pkg.Ctrl.doPost()")
            sink_types = {r["sink_type"] for r in result}
            self.assertIn("sql", sink_types)
            self.assertIn("command", sink_types)


class TestTaintPathFinderCycles(unittest.TestCase):
    """Cyclic call graphs must not cause infinite loops."""

    def test_cyclic_call_graph_terminates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a_fp = _write_java(tmp, "A.java", "  b();")
            b_fp = _write_java(tmp, "B.java", "  a();")  # cycle: A→B→A
            index = {
                "pkg.A.go()": _snapshot("pkg.A.go()", a_fp, calls=["pkg.B.go()"]),
                "pkg.B.go()": _snapshot("pkg.B.go()", b_fp, calls=["pkg.A.go()"]),
            }
            finder = TaintPathFinder(index)
            # Should not hang; SQL sink not reachable
            result = finder.find_reachable_sinks("pkg.A.go()")
            self.assertNotIn("sql", {r["sink_type"] for r in result})


class TestTaintPathFinderPathSink(unittest.TestCase):
    def test_path_sink_detected_via_callee(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl_fp = _write_java(tmp, "Ctrl.java", "  String p = request.getParameter(\"p\");")
            helper_fp = _write_java(
                tmp, "PathHelper.java", "  new java.io.FileInputStream(userInput);"
            )
            index = {
                "pkg.Ctrl.doGet()": _snapshot(
                    "pkg.Ctrl.doGet()", ctrl_fp, calls=["pkg.PathHelper.read()"]
                ),
                "pkg.PathHelper.read()": _snapshot("pkg.PathHelper.read()", helper_fp),
            }
            finder = TaintPathFinder(index)
            result = finder.find_reachable_sinks("pkg.Ctrl.doGet()")
            self.assertIn("path", {r["sink_type"] for r in result})


class TestTaintPathFinderSourceCaching(unittest.TestCase):
    """Source files are read at most once thanks to the internal cache."""

    def test_same_result_on_repeated_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl_fp = _write_java(tmp, "Ctrl.java", "  h();")
            h_fp = _write_java(tmp, "H.java", "  stmt.executeQuery(sql);")
            index = {
                "m.Ctrl.go()": _snapshot("m.Ctrl.go()", ctrl_fp, calls=["m.H.go()"]),
                "m.H.go()": _snapshot("m.H.go()", h_fp),
            }
            finder = TaintPathFinder(index)
            result1 = finder.find_reachable_sinks("m.Ctrl.go()")
            result2 = finder.find_reachable_sinks("m.Ctrl.go()")
            self.assertEqual(result1, result2)


if __name__ == "__main__":
    unittest.main()
