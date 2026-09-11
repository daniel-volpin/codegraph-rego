from __future__ import annotations

import unittest

from codegraph.common.snippet_utils import (
    find_java_block_end_line,
    find_java_statement_end_line,
    select_unique_line_or_refuse,
)
from codegraph.ingestion.service import extract_entities_from_content


class JavaLexicalBoundaryTests(unittest.TestCase):
    def test_block_end_ignores_braces_in_strings_chars_and_comments(self) -> None:
        lines = [
            "class Demo {",
            "  void tricky() {",
            '    String s = "escaped quote \\\" and brace } not code";',
            "    char c = '}';",
            "    // comment with }",
            "    /* block { comment } still comment */",
            "    if (true) {",
            "      int x = 1;",
            "    }",
            "  }",
            "}",
        ]
        self.assertEqual(find_java_block_end_line(lines, 2), 10)

    def test_block_end_handles_nested_blocks(self) -> None:
        lines = [
            "class Demo {",
            "  void nested() {",
            "    if (true) {",
            "      while (false) {",
            "      }",
            "    }",
            "  }",
            "}",
        ]
        self.assertEqual(find_java_block_end_line(lines, 2), 7)

    def test_unbalanced_block_is_rejected(self) -> None:
        lines = [
            "class Demo {",
            "  void broken() {",
            "    if (true) {",
            "      int x = 1;",
            "  ",
        ]
        with self.assertRaises(ValueError):
            find_java_block_end_line(lines, 2)

    def test_unbalanced_statement_is_rejected(self) -> None:
        lines = [
            "class Demo {",
            "  int x = 1",
            "}",
        ]
        with self.assertRaises(ValueError):
            find_java_statement_end_line(lines, 2)

    def test_name_only_ambiguity_refuses_and_start_hint_selects_unique(self) -> None:
        lines = [
            "public class O {",
            "  public void over(int x) {}",
            "  public void over(String x) {}",
            "}",
        ]
        self.assertIsNone(select_unique_line_or_refuse(lines, "over("))
        self.assertEqual(select_unique_line_or_refuse(lines, "over(", start_line_hint=3), 3)

    def test_start_hint_mismatch_refuses_without_fallback(self) -> None:
        lines = [
            "class O {",
            "  void over(int x) {}",
            "  void over(String x) {}",
            "}",
        ]
        self.assertIsNone(select_unique_line_or_refuse(lines, "over(", start_line_hint=1))

    def test_unescaped_newline_in_string_is_rejected(self) -> None:
        lines = [
            "class Demo {",
            "  void broken() {",
            '    String s = "unterminated',
            '    still string";',
            "  }",
            "}",
        ]
        with self.assertRaises(ValueError):
            find_java_block_end_line(lines, 2)

    def test_statement_end_ignores_nested_semicolons_in_initializer(self) -> None:
        lines = [
            "class Demo {",
            "  Runnable r = () -> { int x = 1; System.out.println(x); };",
            "}",
        ]
        self.assertEqual(find_java_statement_end_line(lines, 2), 2)

    def test_statement_depth_underflow_is_rejected(self) -> None:
        lines = [
            "class Demo {",
            "  int x = ) ;",
            "}",
        ]
        with self.assertRaises(ValueError):
            find_java_statement_end_line(lines, 2)


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
        methods, *_ = extract_entities_from_content("Sample.java", source)
        by_full_sig = {m.full_signature: m for m in methods}

        parse = by_full_sig["demo.Sample.parse(T)"]
        self.assertEqual(parse.start_line, 4)
        self.assertEqual(parse.end_line, 13)

        over_int = by_full_sig["demo.Sample.over(int)"]
        over_str = by_full_sig["demo.Sample.over(String)"]
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
        methods, *_ = extract_entities_from_content("EmptyBodies.java", source)
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
        methods, *_ = extract_entities_from_content("SharedLine.java", source)
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
        methods, *_ = extract_entities_from_content("C.java", source)
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
        _, _, _, _, _, _, _, fields, _ = extract_entities_from_content("FieldInit.java", source)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].name, "obj")
        self.assertEqual(fields[0].end_line, 5)

    def test_field_without_declarator_position_uses_field_column_fallback(self) -> None:
        source = """class C { int x = 1;
 void f() {}
}
"""
        _, _, _, _, _, _, _, fields, _ = extract_entities_from_content("C.java", source)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].name, "x")
        self.assertEqual(fields[0].start_line, 1)
        self.assertEqual(fields[0].end_line, 1)

    def test_multi_field_declaration_shared_line_has_correct_end_line(self) -> None:
        source = """class Multi {
  int a = 1, b = 2;
}
"""
        _, _, _, _, _, _, _, fields, _ = extract_entities_from_content("Multi.java", source)
        self.assertEqual({field.name for field in fields}, {"a", "b"})
        self.assertTrue(all(field.end_line == 2 for field in fields))


if __name__ == "__main__":
    unittest.main()
