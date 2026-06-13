"""Tests for codegraph/evaluation/provenance.py.

Provenance capture must:
  * never raise from inside collect_provenance,
  * include schema_version and generated_at,
  * redact credentials from NEO4J_URI,
  * write a deterministic, JSON-serialisable file via write_provenance.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from codegraph.evaluation import provenance as prov_module
from codegraph.evaluation.provenance import (
    _redact_uri,
    collect_provenance,
    write_provenance,
)


class TestRedactUri(unittest.TestCase):
    def test_strips_credentials(self) -> None:
        self.assertEqual(
            _redact_uri("bolt://neo4j:secret@127.0.0.1:7687"),
            "bolt://***@127.0.0.1:7687",
        )

    def test_passthrough_when_no_credentials(self) -> None:
        self.assertEqual(_redact_uri("bolt://127.0.0.1:7687"), "bolt://127.0.0.1:7687")

    def test_handles_none_and_empty(self) -> None:
        self.assertIsNone(_redact_uri(None))
        self.assertEqual(_redact_uri(""), "")


class TestCollectProvenance(unittest.TestCase):
    def test_minimum_shape(self) -> None:
        p = collect_provenance(eval_kind="detection")
        self.assertEqual(p["schema_version"], 1)
        self.assertEqual(p["eval_kind"], "detection")
        self.assertIn("generated_at", p)
        self.assertIn("python", p)
        self.assertIn("platform", p)
        self.assertIn("opa", p)
        self.assertIn("neo4j", p)
        self.assertIsNone(p["seed"])
        self.assertIsNone(p["llm"])

    def test_redacts_neo4j_credentials_from_settings(self) -> None:
        fake_settings = SimpleNamespace(
            neo4j_uri="bolt://neo4j:supersecret@host:7687",
            neo4j_user="neo4j",
        )
        with mock.patch.object(prov_module, "settings", fake_settings):
            p = collect_provenance(eval_kind="explanation")
        self.assertEqual(p["neo4j"]["uri"], "bolt://***@host:7687")
        self.assertEqual(p["neo4j"]["user"], "neo4j")

    def test_includes_seed_and_llm_block(self) -> None:
        p = collect_provenance(
            eval_kind="explanation",
            seed=11,
            llm={"model": "qwen3.5-9b-mlx", "temperature": 0.2, "max_tokens": 192},
        )
        self.assertEqual(p["seed"], 11)
        self.assertEqual(p["llm"]["model"], "qwen3.5-9b-mlx")
        self.assertEqual(p["llm"]["temperature"], 0.2)

    def test_extra_fields_attached(self) -> None:
        p = collect_provenance(eval_kind="remediation", extra={"sample_size": 60})
        self.assertEqual(p["extra"], {"sample_size": 60})

    def test_config_sha256_recorded_when_path_exists(self) -> None:
        with TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg.json"
            cfg.write_text('{"k":1}')
            p = collect_provenance(eval_kind="detection", config_path=cfg)
        self.assertEqual(p["config"]["path"], str(cfg))
        self.assertIsNotNone(p["config"]["sha256"])
        self.assertEqual(len(p["config"]["sha256"]), 64)

    def test_ground_truth_hash_and_corpus_sha_recorded(self) -> None:
        with TemporaryDirectory() as tmp:
            gt = Path(tmp) / "expectedresults-1.2.csv"
            gt.write_text("# test name, category, real vulnerability, cwe\n", encoding="utf-8")
            p = collect_provenance(eval_kind="detection", ground_truth_path=gt)
        self.assertIsNotNone(p["ground_truth"])
        self.assertEqual(p["ground_truth"]["path"], str(gt))
        self.assertEqual(len(p["ground_truth"]["sha256"]), 64)
        # corpus_git_sha may be None outside a git tree, but the key is present.
        self.assertIn("corpus_git_sha", p["ground_truth"])

    def test_ground_truth_missing_file_is_flagged(self) -> None:
        p = collect_provenance(eval_kind="detection", ground_truth_path="/nonexistent/labels.csv")
        self.assertEqual(p["ground_truth"]["error"], "ground_truth_not_found")

    def test_ground_truth_absent_by_default(self) -> None:
        p = collect_provenance(eval_kind="detection")
        self.assertIsNone(p["ground_truth"])

    def test_subprocess_failure_does_not_raise(self) -> None:
        with mock.patch.object(prov_module, "_safe_run", return_value={"error": "command_not_found: opa"}):
            p = collect_provenance(eval_kind="detection")
        self.assertIn("error", p["opa"])
        # git probes also degrade silently to either {} or values=None.
        self.assertIsInstance(p["git"], dict)


class TestWriteProvenance(unittest.TestCase):
    def test_writes_json_file_in_output_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "run_x"
            payload = collect_provenance(eval_kind="detection", output_dir=out_dir, seed=7)
            path = write_provenance(payload, out_dir)
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "provenance.json")
            loaded = json.loads(path.read_text())
            self.assertEqual(loaded["seed"], 7)
            self.assertEqual(loaded["eval_kind"], "detection")
            # File ends with a trailing newline (POSIX habit).
            self.assertTrue(path.read_text().endswith("\n"))


if __name__ == "__main__":
    unittest.main()
