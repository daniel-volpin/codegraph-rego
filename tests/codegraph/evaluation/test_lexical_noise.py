"""Loader contract + fixture/manifest consistency for LexicalNoiseJava.

These tests run in three layers:

  1. Loader contract — parsing, validation, and frozen-view semantics.
  2. Manifest consistency — every declared case_id resolves to a real
     .java file under fixture_root and every fixture file is listed in
     the manifest.
  3. Lexer / fixture cross-check — for every case, applying
     strip_java_lexical_noise to the fixture produces source where the
     declared tokens_in_noise are absent (proving F10 strips them)
     while the active-code tokens stay present (proving F10 does not
     over-strip). This pins the empirical setup before Phase D
     consumes it.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codegraph.evaluation.lexical_noise import (
    VALID_FP_SOURCES,
    LexicalNoiseBenchmark,
    LexicalNoiseCase,
    load_lexical_noise_manifest,
)
from codegraph.policy.source_analysis_core import strip_java_lexical_noise


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = PROJECT_ROOT / "configs" / "benchmark" / "lexical_noise_v1.json"


def _load_benchmark() -> LexicalNoiseBenchmark:
    return load_lexical_noise_manifest(MANIFEST_PATH)


class LoaderContractTests(unittest.TestCase):
    """Pure-data tests that don't touch the real fixtures directory."""

    def _write_manifest(self, tmp: Path, payload: dict) -> Path:
        path = tmp / "manifest.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _valid_payload(self) -> dict:
        return {
            "benchmark_id": "demo",
            "version": 1,
            "description": "fixture demo",
            "fixture_root_relative": "tests/fixtures/demo",
            "java_relative_root": "src/main/java",
            "package": "demo",
            "cases": [
                {
                    "case_id": "D01",
                    "file_name": "D01.java",
                    "fp_source": "line_comment",
                    "expected": "negative",
                    "target_violation_ids": ["ISO-A.10-WEAK-HASH"],
                    "tokens_in_noise": ["MD5"],
                    "rationale": "demo",
                }
            ],
        }

    def test_rejects_missing_required_key(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            del payload["benchmark_id"]
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "benchmark_id"):
                load_lexical_noise_manifest(path)

    def test_rejects_empty_cases(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            payload["cases"] = []
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "non-empty"):
                load_lexical_noise_manifest(path)

    def test_rejects_invalid_fp_source(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            payload["cases"][0]["fp_source"] = "not-a-source"
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "fp_source"):
                load_lexical_noise_manifest(path)

    def test_rejects_invalid_expected(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            payload["cases"][0]["expected"] = "maybe"
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "expected"):
                load_lexical_noise_manifest(path)

    def test_rejects_duplicate_case_ids(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            payload["cases"].append(dict(payload["cases"][0]))
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "duplicate case_id"):
                load_lexical_noise_manifest(path)

    def test_rejects_empty_target_violation_ids(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            payload = self._valid_payload()
            payload["cases"][0]["target_violation_ids"] = []
            path = self._write_manifest(tmp, payload)
            with self.assertRaisesRegex(ValueError, "target_violation_ids"):
                load_lexical_noise_manifest(path)

    def test_frozen_view_returns_typed_case(self) -> None:
        with TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            path = self._write_manifest(tmp, self._valid_payload())
            bench = load_lexical_noise_manifest(path)
            self.assertEqual(len(bench.cases), 1)
            case = bench.cases[0]
            self.assertIsInstance(case, LexicalNoiseCase)
            self.assertEqual(case.case_id, "D01")
            # Tuples (frozen) rather than lists.
            self.assertIsInstance(case.target_violation_ids, tuple)
            self.assertIsInstance(case.tokens_in_noise, tuple)


class RealManifestStructureTests(unittest.TestCase):
    """Asserts the structural design of the curated lexical_noise_v1
    benchmark: 30 cases, 5 fp_sources × 6 each, 1 positive per
    fp_source. These invariants make per-source FP-rate measurement
    well-defined in Phase D.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.bench = _load_benchmark()

    def test_thirty_cases(self) -> None:
        self.assertEqual(len(self.bench.cases), 30)

    def test_five_fp_source_buckets(self) -> None:
        sources = {case.fp_source for case in self.bench.cases}
        self.assertEqual(sources, set(VALID_FP_SOURCES))

    def test_six_cases_per_fp_source(self) -> None:
        for fp_source in VALID_FP_SOURCES:
            self.assertEqual(
                len(self.bench.by_fp_source(fp_source)),
                6,
                f"fp_source {fp_source!r} did not have exactly 6 cases",
            )

    def test_one_positive_per_fp_source(self) -> None:
        for fp_source in VALID_FP_SOURCES:
            cases = self.bench.by_fp_source(fp_source)
            positives = [c for c in cases if c.expected == "positive"]
            self.assertEqual(
                len(positives),
                1,
                f"fp_source {fp_source!r} did not have exactly one positive",
            )

    def test_twenty_five_negatives_total(self) -> None:
        self.assertEqual(len(self.bench.negatives()), 25)

    def test_five_positives_total(self) -> None:
        self.assertEqual(len(self.bench.positives()), 5)

    def test_positives_cover_distinct_controls(self) -> None:
        """For empirical interest each positive targets a different
        control family — verifies F10 doesn't over-strip across
        heterogeneous rules.
        """
        targets = [case.target_violation_ids[0] for case in self.bench.positives()]
        self.assertEqual(len(set(targets)), len(targets))


class FixturePresenceTests(unittest.TestCase):
    """Every manifest case_id resolves to a Java file on disk, and every
    Java file under the fixture root appears in the manifest.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.bench = _load_benchmark()
        cls.java_root = cls.bench.resolve_java_root(PROJECT_ROOT) / cls.bench.package.replace(".", "/")

    def test_manifest_entries_resolve_to_files(self) -> None:
        for case in self.bench.cases:
            path = self.java_root / case.file_name
            self.assertTrue(path.is_file(), f"missing fixture file: {path}")

    def test_fixture_dir_contains_only_manifest_entries(self) -> None:
        on_disk = {p.name for p in self.java_root.glob("*.java")}
        in_manifest = {case.file_name for case in self.bench.cases}
        self.assertEqual(
            on_disk,
            in_manifest,
            f"manifest/disk mismatch: only on disk={on_disk - in_manifest}, only in manifest={in_manifest - on_disk}",
        )


class LexerFixtureCrossCheckTests(unittest.TestCase):
    """The empirical setup is well-formed iff:

      1. for every NEGATIVE case, the substring-safe view of the
         source contains none of the declared tokens_in_noise (proving
         F10's stripping eliminates that FP source for the Rego layer);
      2. for every POSITIVE case, the *active-code* view (literals
         preserved) still contains the substring the target Rego rule
         depends on — proving F10 does not over-strip the legitimate
         pattern when string literals are retained for the Python
         regex pre-analysis layer.

    These checks run on the file contents before any Java parsing,
    Neo4j ingest, or OPA evaluation — they pin the property of the
    lexer/fixture pair so a subsequent Phase D rerun has a stable
    measurement instrument.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.bench = _load_benchmark()
        cls.java_root = cls.bench.resolve_java_root(PROJECT_ROOT) / cls.bench.package.replace(".", "/")

    def _read(self, file_name: str) -> str:
        return (self.java_root / file_name).read_text(encoding="utf-8")

    def test_negative_cases_strip_every_token_in_noise(self) -> None:
        """The substring-safe view (Rego's input.source_code) must not
        contain any of the declared FP-source tokens. This is what
        makes the Rego layer FP-free on noise-only mentions.
        """
        for case in self.bench.negatives():
            raw = self._read(case.file_name)
            substring_safe = strip_java_lexical_noise(raw, strip_string_literals=True)
            for token in case.tokens_in_noise:
                self.assertNotIn(
                    token.lower(),
                    substring_safe.lower(),
                    msg=(
                        f"case {case.case_id} ({case.fp_source}): token {token!r} "
                        f"survived substring-safe cleaning, indicating it appears outside lexical noise"
                    ),
                )

    def test_positive_cases_preserve_active_violation_pattern(self) -> None:
        """The active-code view (string literals preserved) keeps the
        per-case marker the target rule depends on. The Python regex
        pre-analysis layer that drives the analysis_flags pathway
        reads this view, so the rule still fires for these positives.
        Per-case markers below mirror the rule patterns in
        policy/iso_27001_*.rego.
        """
        active_marker_by_case: dict[str, str] = {
            "L06": 'MessageDigest.getInstance("MD5")',
            "L12": "executeQuery",
            "L18": "new Random()",
            "L24": "new FileInputStream",
            "L30": "XPathFactory.newInstance()",
        }
        for case in self.bench.positives():
            marker = active_marker_by_case.get(case.case_id)
            self.assertIsNotNone(
                marker,
                f"positive case {case.case_id} missing an active marker in the cross-check table — update the test",
            )
            active = strip_java_lexical_noise(self._read(case.file_name), strip_string_literals=False)
            self.assertIn(
                marker,
                active,
                msg=(
                    f"case {case.case_id}: active marker {marker!r} was stripped by F10's active-view — "
                    f"either the fixture is wrong or F10 over-strips comments"
                ),
            )

    def test_active_view_preserves_line_count_for_every_fixture(self) -> None:
        for case in self.bench.cases:
            raw = self._read(case.file_name)
            for mode_label, kwargs in (("active", {"strip_string_literals": False}), ("substring_safe", {})):
                cleaned = strip_java_lexical_noise(raw, **kwargs)
                self.assertEqual(
                    cleaned.count("\n"),
                    raw.count("\n"),
                    f"case {case.case_id} ({mode_label} view): cleaned line count drifted from raw",
                )

    def test_active_view_preserves_byte_length_for_every_fixture(self) -> None:
        for case in self.bench.cases:
            raw = self._read(case.file_name)
            for mode_label, kwargs in (("active", {"strip_string_literals": False}), ("substring_safe", {})):
                cleaned = strip_java_lexical_noise(raw, **kwargs)
                self.assertEqual(
                    len(cleaned),
                    len(raw),
                    f"case {case.case_id} ({mode_label} view): cleaned byte length drifted from raw",
                )


class FixtureSyntaxSanityTests(unittest.TestCase):
    """Light surface-level checks that each Java fixture is plausibly
    well-formed: declares the right package, the expected public class,
    and a balanced brace count. These avoid relying on a Java compiler
    being installed in test environments while still catching the kind
    of bug a hand-written fixture is prone to.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.bench = _load_benchmark()
        cls.java_root = cls.bench.resolve_java_root(PROJECT_ROOT) / cls.bench.package.replace(".", "/")

    def test_package_declaration_present(self) -> None:
        decl = f"package {self.bench.package};"
        for case in self.bench.cases:
            src = (self.java_root / case.file_name).read_text(encoding="utf-8")
            self.assertIn(decl, src, f"case {case.case_id}: missing package declaration")

    def test_public_class_matches_filename(self) -> None:
        for case in self.bench.cases:
            class_name = case.file_name.removesuffix(".java")
            src = (self.java_root / case.file_name).read_text(encoding="utf-8")
            pattern = re.compile(rf"\bpublic\s+class\s+{re.escape(class_name)}\b")
            self.assertRegex(
                src,
                pattern,
                f"case {case.case_id}: did not find 'public class {class_name}'",
            )

    def test_braces_balance(self) -> None:
        """Operates on the cleaned source so braces inside comments/
        string-literal contents don't skew the count. The check is a
        coarse sanity guard, not a full parser.
        """
        for case in self.bench.cases:
            raw = (self.java_root / case.file_name).read_text(encoding="utf-8")
            cleaned = strip_java_lexical_noise(raw)
            self.assertEqual(
                cleaned.count("{"),
                cleaned.count("}"),
                f"case {case.case_id}: unbalanced braces in active source",
            )


if __name__ == "__main__":
    unittest.main()
