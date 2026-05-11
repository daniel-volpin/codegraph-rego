"""Round-trip ``detect_text_format`` / ``read_source_preserving_format``
/ ``write_source_preserving_format``.

The remediation apply path used to ``read_text`` and ``write_text`` with
a hardcoded UTF-8 codec, which silently stripped BOMs and rewrote
Windows CRLF endings to LF. These tests pin the new helpers so that
contract regression is caught immediately.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codegraph.remediation.editing import (
    detect_text_format,
    read_source_preserving_format,
    write_source_preserving_format,
)


class DetectTextFormatTests(unittest.TestCase):
    def test_plain_utf8_lf(self) -> None:
        self.assertEqual(detect_text_format(b"hello\nworld\n"), ("utf-8", "\n"))

    def test_utf8_bom_lf(self) -> None:
        self.assertEqual(detect_text_format(b"\xef\xbb\xbfhello\nworld\n"), ("utf-8-sig", "\n"))

    def test_utf8_crlf(self) -> None:
        self.assertEqual(detect_text_format(b"hello\r\nworld\r\n"), ("utf-8", "\r\n"))

    def test_utf8_bom_crlf(self) -> None:
        self.assertEqual(detect_text_format(b"\xef\xbb\xbfhello\r\nworld\r\n"), ("utf-8-sig", "\r\n"))

    def test_mixed_endings_first_is_winning(self) -> None:
        # A single CRLF anywhere in the sample window flips the verdict to CRLF.
        # This is intentional: Java files authored on Windows mix endings if
        # touched by both line-ending-aware and line-ending-naive tools.
        self.assertEqual(detect_text_format(b"hello\nworld\r\n"), ("utf-8", "\r\n"))


class ReadWriteRoundTripTests(unittest.TestCase):
    def _roundtrip(self, raw: bytes) -> bytes:
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.java"
            src.write_bytes(raw)
            text, encoding, newline = read_source_preserving_format(src)
            # No transformation; just write the same text back.
            out = Path(tmp) / "out.java"
            write_source_preserving_format(out, text, encoding, newline)
            return out.read_bytes()

    def test_lf_no_bom_roundtrip_preserves_bytes(self) -> None:
        src = b"public class A {\n  void m() {}\n}\n"
        self.assertEqual(self._roundtrip(src), src)

    def test_crlf_no_bom_roundtrip_preserves_bytes(self) -> None:
        src = b"public class A {\r\n  void m() {}\r\n}\r\n"
        self.assertEqual(self._roundtrip(src), src)

    def test_lf_with_bom_roundtrip_preserves_bytes(self) -> None:
        src = b"\xef\xbb\xbfpublic class A {\n}\n"
        self.assertEqual(self._roundtrip(src), src)

    def test_crlf_with_bom_roundtrip_preserves_bytes(self) -> None:
        src = b"\xef\xbb\xbfpublic class A {\r\n}\r\n"
        self.assertEqual(self._roundtrip(src), src)

    def test_read_returns_lf_normalised_text(self) -> None:
        """Callers should always see ``\\n`` so transformations are uniform."""
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.java"
            src.write_bytes(b"a\r\nb\r\nc\r\n")
            text, encoding, newline = read_source_preserving_format(src)
            self.assertEqual(text, "a\nb\nc\n")
            self.assertEqual(encoding, "utf-8")
            self.assertEqual(newline, "\r\n")

    def test_read_strips_bom_from_text(self) -> None:
        """BOM is preserved as encoding metadata, not as a leading character."""
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.java"
            src.write_bytes(b"\xef\xbb\xbfclass A {}\n")
            text, encoding, newline = read_source_preserving_format(src)
            self.assertEqual(text, "class A {}\n")
            self.assertEqual(encoding, "utf-8-sig")
            self.assertEqual(newline, "\n")


class TransformingRoundTripTests(unittest.TestCase):
    """The realistic use case: read, transform, write; format survives."""

    def test_crlf_file_keeps_crlf_after_transform(self) -> None:
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.java"
            src.write_bytes(b"class A {\r\n  void old() {}\r\n}\r\n")
            text, encoding, newline = read_source_preserving_format(src)
            transformed = text.replace("old", "renamed")
            out = Path(tmp) / "out.java"
            write_source_preserving_format(out, transformed, encoding, newline)
            self.assertEqual(out.read_bytes(), b"class A {\r\n  void renamed() {}\r\n}\r\n")

    def test_bom_file_keeps_bom_after_transform(self) -> None:
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.java"
            src.write_bytes(b"\xef\xbb\xbfclass A {\n  void old() {}\n}\n")
            text, encoding, newline = read_source_preserving_format(src)
            transformed = text.replace("old", "renamed")
            out = Path(tmp) / "out.java"
            write_source_preserving_format(out, transformed, encoding, newline)
            self.assertEqual(out.read_bytes(), b"\xef\xbb\xbfclass A {\n  void renamed() {}\n}\n")


if __name__ == "__main__":
    unittest.main()
