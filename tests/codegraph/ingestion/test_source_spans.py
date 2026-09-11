from __future__ import annotations

import shutil
import unittest
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from codegraph.ingestion.service import collect_code_structure

_TEST_WORK_ROOT = Path(__file__).resolve().parents[3] / ".copilot-source-span-test-work"


@contextmanager
def java_workspace(file_name: str, source: str) -> Iterator[tuple[Path, object]]:
    _TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
    case_dir = _TEST_WORK_ROOT / uuid.uuid4().hex
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        source_path = case_dir / file_name
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="utf-8")
        yield case_dir, collect_code_structure(case_dir.as_posix())
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
        try:
            _TEST_WORK_ROOT.rmdir()
        except OSError:
            pass


def _method_text(source: str, method) -> str:
    source_bytes = source.encode("utf-8")
    assert method.start_byte is not None
    assert method.end_byte is not None
    return source_bytes[method.start_byte : method.end_byte].decode("utf-8")


class JdtRangeBoundaryTests(unittest.TestCase):
    def test_jdt_range_ignores_braces_in_strings_chars_comments_and_text_blocks(self) -> None:
        source = '''package demo;
class Demo {
  void tricky() {
    String s = "escaped quote \\" and brace } not code";
    char c = '}';
    // comment with }
    /* block { comment } still comment */
    String text = """
      braces } and semicolons ; stay in text
      """;
    if (text != null) {
      System.out.println(text);
    }
  }
}
'''
        with java_workspace("Demo.java", source) as (_root, structure):
            method = {m.full_signature: m for m in structure.methods}["demo.Demo.tricky()"]

        self.assertEqual(method.start_line, 3)
        self.assertEqual(method.end_line, 14)
        self.assertIn("braces } and semicolons ;", _method_text(source, method))

    def test_jdt_range_handles_nested_blocks_and_lambda_statement_semicolons(self) -> None:
        source = """package demo;
class Demo {
  void nested() {
    Runnable r = () -> { int x = 1; System.out.println(x); };
    if (true) {
      while (System.currentTimeMillis() < 0) {
      }
    }
  }
}
"""
        with java_workspace("Demo.java", source) as (_root, structure):
            method = {m.full_signature: m for m in structure.methods}["demo.Demo.nested()"]

        self.assertEqual(method.start_line, 3)
        self.assertEqual(method.end_line, 9)
        self.assertIn("Runnable r = () ->", _method_text(source, method))

    def test_jdt_rejects_unbalanced_or_unparseable_sources_before_spans(self) -> None:
        source = """class Broken {
  void broken() {
    if (true) {
      int x = ) ;
}
"""
        from codegraph.ingestion.service import IngestionError

        with self.assertRaises(IngestionError):
            with java_workspace("Broken.java", source):
                pass

    def test_jdt_source_keys_disambiguate_overloads_without_needle_lookup(self) -> None:
        source = """package demo;
class O {
  public void over(int x) {}
  public void over(String x) {}
}
"""
        with java_workspace("O.java", source) as (_root, structure):
            overloads = [method for method in structure.methods if method.name == "over"]

        self.assertEqual({method.full_signature for method in overloads}, {"demo.O.over(int)", "demo.O.over(java.lang.String)"})
        self.assertEqual(len({method.method_key for method in overloads}), 2)
        self.assertTrue(all("#method:over/" in method.method_key for method in overloads))

    def test_jdt_bodyless_interface_method_has_absent_range_not_neighbor_body(self) -> None:
        source = """package demo;
interface Demo {
  void contract();
  default void implemented() {
    int x = 1;
  }
}
"""
        with java_workspace("Demo.java", source) as (_root, structure):
            methods = {m.full_signature: m for m in structure.methods}

        bodyless = methods["demo.Demo.contract()"]
        implemented = methods["demo.Demo.implemented()"]
        self.assertEqual(bodyless.range_status, "verified")
        self.assertEqual(bodyless.start_line, 3)
        self.assertEqual(bodyless.end_line, 3)
        self.assertEqual(implemented.start_line, 4)
        self.assertEqual(implemented.end_line, 6)

    def test_jdt_multiline_annotation_starts_range_at_annotation(self) -> None:
        source = """package demo;
class Annotated {
  @SuppressWarnings({
    "unchecked",
    "deprecation"
  })
  void annotated() {
    int x = 1;
  }
}
"""
        with java_workspace("Annotated.java", source) as (_root, structure):
            method = {m.full_signature: m for m in structure.methods}["demo.Annotated.annotated()"]

        self.assertEqual(method.start_line, 3)
        self.assertEqual(method.end_line, 9)
        self.assertEqual(method.annotations, ["SuppressWarnings"])


class IngestionMethodSpanTests(unittest.TestCase):
    def test_annotated_generic_and_overloaded_methods_have_correct_spans(self) -> None:
        source = """package demo;
class Sample {
  @Deprecated
  public <T> T parse(T input) {
    String s = "escaped quote \\" and brace } not code";
    char c = '}';
    // } comment brace
    /* { block } comment */
    if (input != null) {
      return input;
    }
    return null;
  }

  public void over(int x) {
    int y = x + 1;
  }

  public void over(String x) {
    String y = x + "{}";
  }
}
"""
        with java_workspace("Sample.java", source) as (_root, structure):
            methods = structure.methods
        by_full_sig = {m.full_signature: m for m in methods}

        parse = by_full_sig["demo.Sample.parse(T)"]
        self.assertEqual(parse.start_line, 3)
        self.assertEqual(parse.end_line, 13)

        over_int = by_full_sig["demo.Sample.over(int)"]
        over_str = by_full_sig["demo.Sample.over(java.lang.String)"]
        self.assertEqual(over_int.start_line, 15)
        self.assertEqual(over_int.end_line, 17)
        self.assertEqual(over_str.start_line, 19)
        self.assertEqual(over_str.end_line, 21)

    def test_empty_and_comment_only_bodies_resolve_closing_line(self) -> None:
        source = """package demo;
class EmptyBodies {
  void empty() {
  }
  EmptyBodies() {
  }
  void commentOnly() {
    // comment
    /* block */
  }
}
"""
        with java_workspace("EmptyBodies.java", source) as (_root, structure):
            methods = structure.methods
        by_full_sig = {m.full_signature: m for m in methods}
        self.assertEqual(by_full_sig["demo.EmptyBodies.empty()"].end_line, 4)
        self.assertEqual(by_full_sig["demo.EmptyBodies.EmptyBodies()"].end_line, 6)
        self.assertEqual(by_full_sig["demo.EmptyBodies.commentOnly()"].end_line, 10)

    def test_column_anchor_avoids_wrong_brace_on_shared_lines(self) -> None:
        source = """package demo;
class SharedLine { void a() {} void b() {
  int x = 1;
}
}
"""
        with java_workspace("SharedLine.java", source) as (_root, structure):
            methods = structure.methods
        by_full_sig = {m.full_signature: m for m in methods}
        self.assertEqual(by_full_sig["demo.SharedLine.a()"].end_line, 2)
        self.assertEqual(by_full_sig["demo.SharedLine.b()"].end_line, 4)

    def test_class_open_and_method_open_same_line_uses_method_column(self) -> None:
        source = """package demo;
class C { void f() {
  int x = 1;
}
}
"""
        with java_workspace("C.java", source) as (_root, structure):
            methods = structure.methods
        by_full_sig = {m.full_signature: m for m in methods}
        self.assertEqual(by_full_sig["demo.C.f()"].start_line, 2)
        self.assertEqual(by_full_sig["demo.C.f()"].end_line, 4)

    def test_field_initializer_with_anonymous_class_keeps_outer_statement(self) -> None:
        source = """package demo;
class FieldInit {
  Object obj = new Object() {
    void inner() { int x = 1; }
  };
}
"""
        with java_workspace("FieldInit.java", source) as (_root, structure):
            fields = structure.fields
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].name, "obj")
        self.assertEqual(fields[0].end_line, 5)

    def test_field_without_declarator_position_uses_field_column_fallback(self) -> None:
        source = """class C { int x = 1;
 void f() {}
}
"""
        with java_workspace("C.java", source) as (_root, structure):
            fields = structure.fields
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].name, "x")
        self.assertEqual(fields[0].start_line, 1)
        self.assertEqual(fields[0].end_line, 1)

    def test_multi_field_declaration_shared_line_has_correct_end_line(self) -> None:
        source = """class Multi {
  int a = 1, b = 2;
}
"""
        with java_workspace("Multi.java", source) as (_root, structure):
            fields = structure.fields
        self.assertEqual({field.name for field in fields}, {"a", "b"})
        self.assertTrue(all(field.end_line == 2 for field in fields))


if __name__ == "__main__":
    unittest.main()
