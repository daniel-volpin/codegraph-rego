import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codegraph.benchmark_registry import framework_demo_category_ids, framework_demo_rule_ids, policy_catalog_payload_from_registry
from tests._support import PROJECT_ROOT


SCRIPT_PATH = PROJECT_ROOT / "scripts" / "evaluation" / "build_benchmark_demo_pack.py"
MANIFEST_PATH = PROJECT_ROOT / "demo" / "benchmark-framework-demo" / "manifest.json"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("build_benchmark_demo_pack", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load build_benchmark_demo_pack.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkDemoPackTests(unittest.TestCase):
    def test_framework_demo_manifest_matches_registry_and_api_payload(self) -> None:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        testcases = payload.get("testcases", [])
        manifest_rule_ids = [entry["rego_rule"] for entry in testcases if isinstance(entry, dict)]
        manifest_category_ids = [entry["category_id"] for entry in testcases if isinstance(entry, dict)]

        self.assertEqual(sorted(set(manifest_rule_ids)), sorted(framework_demo_rule_ids()))
        self.assertEqual(sorted(set(manifest_category_ids)), sorted(framework_demo_category_ids()))

        api_payload = policy_catalog_payload_from_registry()
        self.assertEqual(api_payload["framework_demo_rule_ids"], framework_demo_rule_ids())
        demo_categories = {
            entry["category_id"]
            for entry in api_payload["benchmark_categories"]
            if entry.get("framework_demo")
        }
        self.assertEqual(demo_categories, set(framework_demo_category_ids()))

    def test_build_demo_pack_copies_selected_assets_and_creates_zip(self) -> None:
        module = _load_script_module()

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            benchmark_root = root / "BenchmarkJava"
            output_dir = root / "output"
            manifest_path = root / "manifest.json"

            (benchmark_root / ".mvn").mkdir(parents=True)
            (benchmark_root / "src" / "main" / "resources").mkdir(parents=True)
            (benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "helpers").mkdir(
                parents=True
            )
            testcase_dir = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
            testcase_dir.mkdir(parents=True)

            (benchmark_root / "pom.xml").write_text("<project />\n", encoding="utf-8")
            (benchmark_root / "mvnw").write_text("#!/bin/sh\n", encoding="utf-8")
            (benchmark_root / "src" / "main" / "resources" / "benchmark.properties").write_text(
                "key=value\n",
                encoding="utf-8",
            )
            (benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "helpers" / "Thing.java").write_text(
                "package org.owasp.benchmark.helpers;\nclass Thing {}\n",
                encoding="utf-8",
            )
            (testcase_dir / "BenchmarkTest00046.java").write_text(
                "package org.owasp.benchmark.testcode;\nclass BenchmarkTest00046 {}\n",
                encoding="utf-8",
            )

            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "benchmark-framework-demo",
                        "testcases": [
                            {
                                "category_id": "hash-md5",
                                "rego_rule": "ISO-A.10-WEAK-HASH",
                                "testcase_id": "BenchmarkTest00046",
                            },
                            {
                                "category_id": "rng-insecure",
                                "rego_rule": "ISO-A.10-WEAK-RANDOM",
                                "testcase_id": "BenchmarkTest00083",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            (testcase_dir / "BenchmarkTest00083.java").write_text(
                "package org.owasp.benchmark.testcode;\nclass BenchmarkTest00083 {}\n",
                encoding="utf-8",
            )

            result = module.build_demo_pack(benchmark_root, manifest_path, output_dir)

            pack_root = Path(result["pack_root"])
            self.assertTrue((pack_root / "pom.xml").is_file())
            self.assertTrue((pack_root / "mvnw").is_file())
            self.assertTrue((pack_root / "src" / "main" / "resources" / "benchmark.properties").is_file())
            self.assertTrue(
                (
                    pack_root
                    / "src"
                    / "main"
                    / "java"
                    / "org"
                    / "owasp"
                    / "benchmark"
                    / "helpers"
                    / "Thing.java"
                ).is_file()
            )
            self.assertTrue(
                (
                    pack_root
                    / "src"
                    / "main"
                    / "java"
                    / "org"
                    / "owasp"
                    / "benchmark"
                    / "testcode"
                    / "BenchmarkTest00046.java"
                ).is_file()
            )
            self.assertTrue(Path(result["zip_path"]).is_file())
            self.assertEqual(result["testcase_ids"], ["BenchmarkTest00046", "BenchmarkTest00083"])

    def test_build_demo_pack_raises_for_missing_testcase(self) -> None:
        module = _load_script_module()

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            benchmark_root = root / "BenchmarkJava"
            manifest_path = root / "manifest.json"
            output_dir = root / "output"

            (benchmark_root / "src" / "main" / "java").mkdir(parents=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "benchmark-framework-demo",
                        "testcases": [
                            {
                                "category_id": "hash-md5",
                                "rego_rule": "ISO-A.10-WEAK-HASH",
                                "testcase_id": "BenchmarkTest99999",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(FileNotFoundError):
                module.build_demo_pack(benchmark_root, manifest_path, output_dir)
