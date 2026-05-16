"""Java-aware lexical-noise stripping.

These tests pin the behaviour of ``strip_java_lexical_noise`` against
every class of false-positive source the function is designed to
address:

* line comments (``// ...``)
* block comments (``/* ... */``)
* javadoc (``/** ... */``)
* char literals
* string literals (with ``\\"`` escape)
* text blocks (Java 13+)

They also pin the contract that line numbers and per-line character
offsets in the cleaned string match the input exactly, which is what
the evidence-card citation grounding relies on.
"""

from __future__ import annotations

import unittest

from codegraph.policy.source_analysis_core import strip_java_lexical_noise


class OffsetPreservationTests(unittest.TestCase):
    """Cleaned output must have identical length and identical line layout."""

    def test_length_preserved_for_plain_code(self) -> None:
        src = "int x = 1;\nint y = 2;\n"
        out = strip_java_lexical_noise(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out, src)

    def test_length_preserved_with_comments(self) -> None:
        src = "int x = 1; // hello\nint y = 2; /* world */\n"
        out = strip_java_lexical_noise(src)
        self.assertEqual(len(out), len(src))

    def test_line_count_preserved_through_multi_line_block_comment(self) -> None:
        src = "/* line 1\nline 2\nline 3 */\nint x = 1;\n"
        out = strip_java_lexical_noise(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        # Last line is real code; must survive intact.
        self.assertIn("int x = 1;", out)

    def test_per_line_length_preserved(self) -> None:
        """The N-th line of the cleaned output has the same length as the
        N-th line of the input. This is what the citation snippet
        extractor relies on.
        """
        src = 'class A {\n  // MD5 here\n  String s = "MessageDigest";\n}\n'
        out = strip_java_lexical_noise(src)
        in_lines = src.split("\n")
        out_lines = out.split("\n")
        self.assertEqual(len(in_lines), len(out_lines))
        for in_line, out_line in zip(in_lines, out_lines):
            self.assertEqual(len(in_line), len(out_line))


class LineCommentTests(unittest.TestCase):
    def test_line_comment_with_token_is_blanked(self) -> None:
        src = '// MessageDigest.getInstance("MD5")\nint x = 1;\n'
        out = strip_java_lexical_noise(src)
        self.assertNotIn("MD5", out)
        self.assertNotIn("MessageDigest", out)
        self.assertIn("int x = 1;", out)

    def test_double_slash_inside_string_is_not_a_comment(self) -> None:
        src = 'String url = "http://example.com/path";\n'
        out = strip_java_lexical_noise(src)
        # The string content is blanked, but the assignment statement structure remains.
        self.assertNotIn("http", out)
        self.assertIn("String url =", out)
        self.assertIn(";", out)


class BlockCommentTests(unittest.TestCase):
    def test_block_comment_with_token_is_blanked(self) -> None:
        src = '/* uses executeQuery( internally */\nint x = 1;\n'
        out = strip_java_lexical_noise(src)
        self.assertNotIn("executeQuery", out)
        self.assertIn("int x = 1;", out)

    def test_javadoc_with_token_is_blanked(self) -> None:
        src = """/**
 * MessageDigest.getInstance("MD5") is deprecated; use SHA-256.
 */
public String hash() { return ""; }
"""
        out = strip_java_lexical_noise(src)
        self.assertNotIn("MD5", out)
        self.assertNotIn("MessageDigest", out)
        # Method declaration must still parse.
        self.assertIn("public String hash()", out)

    def test_double_slash_inside_block_comment_does_not_open_line_comment(self) -> None:
        # The line comment "//" sits inside the block; it must not affect state.
        src = '/* hello // world */\nint x = 1;\n'
        out = strip_java_lexical_noise(src)
        self.assertIn("int x = 1;", out)

    def test_block_comment_terminator_inside_a_string_is_not_a_terminator(self) -> None:
        # An asterisk-slash inside a string literal must not close a block comment
        # because we're never in block-comment state inside a string.
        src = 'String s = "*/";\nint x = 1;\n'
        out = strip_java_lexical_noise(src)
        self.assertIn("int x = 1;", out)


class StringLiteralTests(unittest.TestCase):
    def test_string_literal_with_token_is_blanked(self) -> None:
        src = 'String label = "MessageDigest.getInstance(\\"MD5\\")";\nint x = 1;\n'
        out = strip_java_lexical_noise(src)
        self.assertNotIn("MD5", out)
        self.assertNotIn("MessageDigest", out)
        self.assertIn("int x = 1;", out)

    def test_escaped_quote_does_not_close_string(self) -> None:
        # The \" inside should not terminate the string; the next " does.
        src = 'String s = "say \\"hi\\" loud";\nint y = 2;\n'
        out = strip_java_lexical_noise(src)
        self.assertNotIn("hi", out)
        self.assertNotIn("loud", out)
        self.assertIn("int y = 2;", out)

    def test_escaped_backslash_then_quote_closes_string(self) -> None:
        # "a\\" is a string whose content is a single backslash; the
        # following " then opens a NEW string (which is closed by the ;).
        # We check that the cleaner doesn't misinterpret and consume the
        # rest of the file.
        src = 'String s = "a\\\\";\nint z = 3;\n'
        out = strip_java_lexical_noise(src)
        self.assertIn("int z = 3;", out)


class CharLiteralTests(unittest.TestCase):
    def test_char_literal_with_token_chars_is_blanked(self) -> None:
        src = "char c = 'M';\nchar d = 'D';\nchar e = '5';\nint x = 1;\n"
        out = strip_java_lexical_noise(src)
        # The single chars themselves should not appear as bare letters.
        self.assertIn("char c =", out)
        self.assertIn("char d =", out)
        self.assertIn("int x = 1;", out)

    def test_escaped_apostrophe(self) -> None:
        src = "char apostrophe = '\\'';\nint x = 1;\n"
        out = strip_java_lexical_noise(src)
        self.assertIn("int x = 1;", out)


class TextBlockTests(unittest.TestCase):
    """Java 13+ text blocks delimited by triple double quotes."""

    def test_text_block_content_is_blanked(self) -> None:
        src = '''String poem = """
            MessageDigest.getInstance("MD5")
            is deprecated here.
            """;
int x = 1;
'''
        out = strip_java_lexical_noise(src)
        self.assertNotIn("MessageDigest", out)
        self.assertNotIn("MD5", out)
        self.assertIn("int x = 1;", out)
        # Line count preserved despite multi-line text block.
        self.assertEqual(out.count("\n"), src.count("\n"))

    def test_single_double_quote_inside_text_block_does_not_close_it(self) -> None:
        src = '''String s = """
            here is one " quote, and two "" quotes, but the block closes only on three.
            """;
int x = 1;
'''
        out = strip_java_lexical_noise(src)
        self.assertIn("int x = 1;", out)


class LineTerminatorSpecComplianceTests(unittest.TestCase):
    """JLS §3.4: a line terminator is LF, CR, or CRLF. A line comment
    is terminated by any of these. The cleaner must preserve every
    terminator verbatim so line-counting consumers (citation grounding,
    progress markers) see the same line boundaries as the input.
    """

    def test_crlf_line_endings_preserve_length(self) -> None:
        src = "// foo\r\nint x = 1;\r\n"
        out = strip_java_lexical_noise(src)
        self.assertEqual(len(out), len(src))
        # Both \r and \n are preserved verbatim.
        self.assertEqual(out[6], "\r")
        self.assertEqual(out[7], "\n")

    def test_cr_only_terminates_line_comment(self) -> None:
        """Mac-classic line endings (CR only) are vanishingly rare in
        modern Java but the JLS §3.4 spec mandates CR as a line
        terminator. A token mentioned on a code line that follows a
        \\r-terminated comment must still survive cleaning.
        """
        src = "// MD5 here\rint x = MessageDigest.getInstance(\"MD5\");"
        out = strip_java_lexical_noise(src)
        # The first 'MD5' lives in the comment and must be blanked.
        # The second 'MD5' lives in a string literal and is also blanked.
        # But the active code 'int x = MessageDigest.getInstance(' must
        # survive — proving the CR did terminate the comment.
        self.assertIn("int x = MessageDigest.getInstance(", out)

    def test_cr_in_string_literal_closes_defensively(self) -> None:
        """A CR (or LF) inside an unterminated string literal is a Java
        syntax error; the lexer must close the literal defensively so
        the rest of the file is parsed as code, not as a runaway string.
        """
        src = 'String x = "broken\rMessageDigest.getInstance("MD5");'
        out = strip_java_lexical_noise(src)
        # After the defensive close the post-CR text is back in code state;
        # the MessageDigest call must survive (its substring 'MessageDigest'
        # is visible in the active view).
        self.assertIn("MessageDigest.getInstance(", out)

    def test_cr_in_char_literal_closes_defensively(self) -> None:
        src = "char c = 'a\rint y = 0;"
        out = strip_java_lexical_noise(src)
        self.assertIn("int y = 0", out)


class FpEliminationSmokeTests(unittest.TestCase):
    """End-to-end: the kind of source that motivated F10."""

    def test_md5_in_doc_comment_only_does_not_appear_in_active_code(self) -> None:
        src = '''/**
 * Note: MessageDigest.getInstance("MD5") is deprecated.
 * Use MessageDigest.getInstance("SHA-256") instead.
 */
public byte[] hash(String input) {
    return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
}
'''
        cleaned = strip_java_lexical_noise(src).lower()
        # The substring 'getinstance("md5"' (lowered, with the escaped quote
        # collapsed to just the quote in lowered form) must not be present.
        self.assertNotIn('messagedigest.getinstance("md5"', cleaned)
        # The actual production line using SHA-256 survives.
        self.assertIn("messagedigest.getinstance(", cleaned)

    def test_executequery_in_string_literal_only_does_not_match_pattern(self) -> None:
        src = '''public String description() {
    return "Use prepareStatement, not executeQuery(...) -- prevents SQLi.";
}
'''
        cleaned = strip_java_lexical_noise(src).lower()
        self.assertNotIn("executequery(", cleaned)
        self.assertNotIn("preparestatement", cleaned)


class DualModeLexerTests(unittest.TestCase):
    """``strip_string_literals=False`` retains literal contents while still
    blanking comments. This is the *active-code* view the Python regex
    pre-analysis layer needs in order to keep matching algorithm names
    that legitimately live inside string-literal arguments.
    """

    def test_default_mode_strips_literals(self) -> None:
        src = 'String s = "MD5";\n'
        cleaned = strip_java_lexical_noise(src)
        self.assertNotIn("MD5", cleaned)
        # Default kwarg is True (substring-safe).
        self.assertEqual(cleaned, strip_java_lexical_noise(src, strip_string_literals=True))

    def test_active_mode_preserves_string_literal_contents(self) -> None:
        src = 'MessageDigest.getInstance("MD5");\n'
        active = strip_java_lexical_noise(src, strip_string_literals=False)
        self.assertIn('"MD5"', active)
        self.assertIn("MessageDigest.getInstance(", active)

    def test_active_mode_still_strips_comments(self) -> None:
        src = '// MD5 was here\nString s = "ok";\n'
        active = strip_java_lexical_noise(src, strip_string_literals=False)
        self.assertNotIn("MD5", active)  # comment was stripped
        self.assertIn('"ok"', active)  # literal content preserved

    def test_active_mode_preserves_text_block_contents(self) -> None:
        src = '''String s = """
                MessageDigest.getInstance("MD5")
                """;
'''
        active = strip_java_lexical_noise(src, strip_string_literals=False)
        # Text-block content is preserved in active mode.
        self.assertIn("MessageDigest.getInstance", active)
        self.assertIn('"MD5"', active)

    def test_active_mode_preserves_char_literal_value(self) -> None:
        src = "char c = 'M';\n"
        active = strip_java_lexical_noise(src, strip_string_literals=False)
        self.assertIn("'M'", active)

    def test_both_modes_preserve_byte_length_and_line_count(self) -> None:
        src = '''/**
 * doc: MD5 is bad
 */
public byte[] hash() throws Exception {
    String name = "MessageDigest.getInstance(\\"MD5\\")";
    return MessageDigest.getInstance("MD5").digest(new byte[]{ 'a', 'b' });
}
'''
        for mode in (True, False):
            cleaned = strip_java_lexical_noise(src, strip_string_literals=mode)
            self.assertEqual(len(cleaned), len(src), f"mode={mode}: byte length drifted")
            self.assertEqual(cleaned.count("\n"), src.count("\n"), f"mode={mode}: line count drifted")


if __name__ == "__main__":
    unittest.main()
