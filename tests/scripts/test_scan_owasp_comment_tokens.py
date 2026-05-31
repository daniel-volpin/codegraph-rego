from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.scan_owasp_comment_tokens import iter_java_comments, scan


class OwaspCommentTokenScanTest(unittest.TestCase):
    def test_iter_java_comments_ignores_literals(self) -> None:
        source = """
class Example {
  String s = "MD5 MessageDigest executeQuery";
  char c = '/';
  String text = \"""
    ProcessBuilder
  \""";
  // MD5 MessageDigest
  /* executeQuery
     ProcessBuilder
     new Random
     XPathFactory */
}
"""

        comments = list(iter_java_comments(source))

        self.assertEqual(len(comments), 2)
        self.assertIn("MD5 MessageDigest", comments[0])
        self.assertIn("executeQuery", comments[1])
        self.assertNotIn("String s", "\n".join(comments))

    def test_scan_counts_tokens_in_comments_only(self) -> None:
        with TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "BenchmarkTest00001.java"
            java_file.write_text(
                """
class Example {
  String ignored = "MD5 MessageDigest executeQuery ProcessBuilder new Random XPathFactory";
  // MD5 MessageDigest
  /* executeQuery ProcessBuilder new Random XPathFactory */
}
""",
                encoding="utf-8",
            )

            result = scan([java_file])

        self.assertEqual(
            result["token_counts_in_comments"],
            {
                "MD5": 1,
                "MessageDigest": 1,
                "executeQuery": 1,
                "ProcessBuilder": 1,
                "new Random": 1,
                "XPathFactory": 1,
            },
        )
        self.assertEqual(result["total_comment_occurrences"], 6)
        self.assertEqual(result["total_comment_blocks_scanned"], 2)


if __name__ == "__main__":
    unittest.main()
