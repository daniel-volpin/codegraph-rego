"""Unit tests for pluggable policy packs and registry."""

from __future__ import annotations

import itertools
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from codegraph.policy.packs import loader
from codegraph.policy.packs.loader import PolicyPackRegistry
from codegraph.policy.packs.models import PolicyPackSpec, PolicyRuleDefinition


class TestPolicyPacks(unittest.TestCase):
    def test_default_compliance_packs_discovered(self) -> None:
        registry = PolicyPackRegistry()
        packs = registry.list_packs()
        self.assertGreaterEqual(len(packs), 4)
        pack_ids = {p.pack_id for p in packs}
        self.assertIn("iso-27001", pack_ids)
        self.assertIn("pci-dss-4.0", pack_ids)
        self.assertIn("owasp-top10-2021", pack_ids)
        self.assertIn("nist-sp-800-53", pack_ids)

    def test_custom_pack_registration(self) -> None:
        registry = PolicyPackRegistry()
        initial_count = len(registry.list_packs())
        rule = PolicyRuleDefinition(
            id="CUSTOM-1.0",
            control="CUSTOM-A.1",
            title="Custom Security Rule",
            summary="Custom policy check.",
            rego_module="custom",
            rego_rule="check",
            severity="critical",
        )
        custom_pack = PolicyPackSpec(
            pack_id="custom-pack",
            name="Custom Organization Pack",
            standard="Custom",
            version="1.0.0",
            rego_dir=Path("/tmp/custom"),
            query_entrypoints=("data.custom.violations",),
            rules=(rule,),
        )
        registry.register_pack(custom_pack)

        self.assertEqual(len(registry.list_packs()), initial_count + 1)
        pci = registry.get_pack("custom-pack")
        self.assertIsNotNone(pci)
        assert pci is not None
        self.assertEqual(pci.name, "Custom Organization Pack")
        self.assertEqual(registry.get_rule("CUSTOM-1.0"), rule)

    def test_load_pack_from_manifest(self) -> None:
        registry = PolicyPackRegistry()
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_file = Path(tmp_dir) / "pack_manifest.json"
            manifest_data = {
                "pack_id": "nist-800-53",
                "name": "NIST SP 800-53 Security Controls",
                "standard": "NIST",
                "version": "5.0.0",
                "query_entrypoints": ["data.nist.violations"],
                "rules": [
                    {
                        "id": "NIST-SI-10",
                        "control": "SI-10",
                        "title": "Information Input Validation",
                        "summary": "Check for improper input sanitization.",
                        "rego_module": "nist",
                        "rego_rule": "input_validation",
                    }
                ],
            }
            manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

            pack = registry.load_pack_from_manifest(manifest_file)
            self.assertEqual(pack.pack_id, "nist-800-53")
            self.assertEqual(len(pack.rules), 1)
            self.assertEqual(pack.rules[0].id, "NIST-SI-10")


class TestPolicyPacksApi(unittest.TestCase):
    def test_list_packs_endpoint(self) -> None:
        from api.routers.policy import router as policy_router

        app = FastAPI()
        app.include_router(policy_router)
        client = TestClient(app)

        response = client.get("/policy/packs")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "OK")
        self.assertGreaterEqual(len(data["packs"]), 1)


if __name__ == "__main__":
    unittest.main()


class TestRegistrySingletonUnderConcurrency(unittest.TestCase):
    """Policy evaluation is thread-pooled, so the lazy singleton must construct once.

    Two registries were being built on first use: threads raced the
    ``is None`` check, and the loser's instance was discarded. Identical
    on-disk manifests made that invisible except as duplicated log lines,
    but a pack registered at runtime on one instance is absent from the other.
    """

    def setUp(self) -> None:
        self._saved = loader._GLOBAL_REGISTRY
        loader._GLOBAL_REGISTRY = None

    def tearDown(self) -> None:
        loader._GLOBAL_REGISTRY = self._saved

    def test_concurrent_first_use_constructs_one_registry(self) -> None:
        workers = 16
        constructed = itertools.count()
        original_init = loader.PolicyPackRegistry.__init__

        def counting_init(self, *args, **kwargs):
            next(constructed)
            original_init(self, *args, **kwargs)

        start = threading.Barrier(workers)

        def worker():
            start.wait()
            return loader.get_policy_pack_registry()

        with mock.patch.object(loader.PolicyPackRegistry, "__init__", counting_init):
            with ThreadPoolExecutor(max_workers=workers) as pool:
                registries = [f.result() for f in [pool.submit(worker) for _ in range(workers)]]

        self.assertEqual(next(constructed), 1, "registry constructed more than once")
        self.assertEqual(len({id(r) for r in registries}), 1, "threads saw different registries")

    def test_runtime_registration_is_visible_to_every_caller(self) -> None:
        """The consequence the race would cause, asserted directly."""
        rule = PolicyRuleDefinition(
            id="RACE-1.0",
            control="RACE-A.1",
            title="Runtime registered rule",
            summary="",
            rego_module="race",
            rego_rule="check",
        )
        loader.get_policy_pack_registry().register_pack(
            PolicyPackSpec(
                pack_id="race-pack",
                name="Race Pack",
                standard="Custom",
                version="1.0.0",
                rego_dir=loader.DEFAULT_POLICY_DIR,
                query_entrypoints=("data.race.violations",),
                rules=(rule,),
            )
        )

        def lookup():
            return loader.get_policy_pack_registry().get_rule("RACE-1.0")

        with ThreadPoolExecutor(max_workers=8) as pool:
            found = [f.result() for f in [pool.submit(lookup) for _ in range(8)]]

        self.assertTrue(all(r is not None for r in found), "a caller lost the runtime-registered pack")
