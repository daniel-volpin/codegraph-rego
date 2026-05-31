from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluation.check_thesis_artifacts import ROOT, validate_manifest


class ThesisArtifactCheckerTest(unittest.TestCase):
    def test_canonical_manifest_passes(self) -> None:
        manifest = ROOT / "outputs" / "thesis_canonical_2026-05-31" / "manifest.json"
        self.assertEqual(validate_manifest(manifest), [])

    def test_rejects_overclaimed_remediation(self) -> None:
        manifest_path = ROOT / "outputs" / "thesis_canonical_2026-05-31" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        edited = copy.deepcopy(manifest)
        for claim in edited["claims"]:
            if claim["claim_id"] == "remediation_pr_reproducibility_19_of_25":
                claim["metrics"]["fix_success"] = 25
                break

        with tempfile.TemporaryDirectory() as tmp:
            bad_manifest = Path(tmp) / "manifest.json"
            bad_manifest.write_text(json.dumps(edited), encoding="utf-8")
            errors = validate_manifest(bad_manifest)

        self.assertIn("canonical remediation must not be labelled 25/25", errors)


if __name__ == "__main__":
    unittest.main()
