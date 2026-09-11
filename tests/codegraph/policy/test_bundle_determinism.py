"""Determinism regression for graph-context ordering in evidence bundles.

Neo4j ``collect(DISTINCT ...)`` returns lists in an undefined order. The bundle
builder must sort ``calls`` / ``callers`` / ``uses_fields`` so promoted artifacts
are byte-stable across reruns. Detection is unaffected (Rego sink checks are
any-match) — this only removes run-to-run noise.
"""

import unittest

from codegraph.policy.runtime.bundles import fetch_method_snapshot, fetch_methods_with_context
from tests.codegraph.policy._test_helpers import _FakeDriver


def _record(calls, callers, uses_fields):
    return {
        "method_key": "workspace@revision:Foo.java#method:bar",
        "signature": "com.example.Foo.bar()",
        "name": "bar",
        "file_path": "/work/Foo.java",
        "start_line": 1,
        "end_line": 5,
        "modifiers": [],
        "declaring_type_key": "workspace@revision:Foo.java#type:Foo",
        "relative_path": "Foo.java",
        "start_byte": 0,
        "end_byte": 10,
        "property_annotations": [],
        "annotation_nodes": [],
        "uses_fields": uses_fields,
        "calls": calls,
        "callers": callers,
        "workspace_id": "workspace",
        "revision_id": "revision",
        "parser_backend": "eclipse-jdt",
        "parser_version": "3.47.0",
        "source_sha256": "f" * 64,
        "range_status": "verified",
    }


class BundleDeterminismTests(unittest.TestCase):
    def test_calls_callers_uses_fields_are_sorted(self) -> None:
        record = _record(
            calls=["z.C.c()", "a.A.a()", "m.M.m()"],
            callers=["q.Q.q()", "b.B.b()"],
            uses_fields=[{"name": "zeta"}, {"name": "alpha"}, {"name": "mu"}],
        )
        snapshots = fetch_methods_with_context(_FakeDriver([record]))
        self.assertEqual(len(snapshots), 1)
        snap = snapshots[0]
        self.assertEqual(snap["calls"], ["a.A.a()", "m.M.m()", "z.C.c()"])
        self.assertEqual(snap["callers"], ["b.B.b()", "q.Q.q()"])
        self.assertEqual([f["name"] for f in snap["uses_fields"]], ["alpha", "mu", "zeta"])

    def test_ordering_is_stable_regardless_of_input_order(self) -> None:
        forward = _record(["b()", "a()", "c()"], ["y()", "x()"], [{"name": "b"}, {"name": "a"}])
        reverse = _record(["c()", "a()", "b()"], ["x()", "y()"], [{"name": "a"}, {"name": "b"}])
        snap_fwd = fetch_methods_with_context(_FakeDriver([forward]))[0]
        snap_rev = fetch_methods_with_context(_FakeDriver([reverse]))[0]
        self.assertEqual(snap_fwd["calls"], snap_rev["calls"])
        self.assertEqual(snap_fwd["callers"], snap_rev["callers"])
        self.assertEqual(snap_fwd["uses_fields"], snap_rev["uses_fields"])

    def test_single_method_snapshot_uses_same_stable_ordering(self) -> None:
        record = _record(
            calls=["z.C.c()", "a.A.a()", "m.M.m()"],
            callers=["q.Q.q()", "b.B.b()"],
            uses_fields=[{"name": "zeta"}, {"name": "alpha"}, {"name": "mu"}],
        )
        snap = fetch_method_snapshot(_FakeDriver([record]), "com.example.Foo.bar()")
        self.assertIsNotNone(snap)
        self.assertEqual(snap["calls"], ["a.A.a()", "m.M.m()", "z.C.c()"])
        self.assertEqual(snap["callers"], ["b.B.b()", "q.Q.q()"])
        self.assertEqual([f["name"] for f in snap["uses_fields"]], ["alpha", "mu", "zeta"])


if __name__ == "__main__":
    unittest.main()
