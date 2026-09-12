"""Unit tests for pluggable policy packs and registry."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from codegraph.policy.packs.loader import PolicyPackRegistry
from codegraph.policy.packs.models import PolicyPackSpec, PolicyRuleDefinition


class TestPolicyPacks(unittest.TestCase):
    def test_default_iso_pack_registered(self) -> None:
        registry = PolicyPackRegistry()
        packs = registry.list_packs()
        self.assertGreaterEqual(len(packs), 1)
        iso_pack = registry.get_pack("iso-27001")
        self.assertIsNotNone(iso_pack)
        assert iso_pack is not None
        self.assertEqual(iso_pack.standard, "ISO-27001")
        self.assertTrue(iso_pack.enabled)
        self.assertIn("data.iso27001.violations", iso_pack.query_entrypoints)

    def test_custom_pack_registration(self) -> None:
        registry = PolicyPackRegistry()
        rule = PolicyRuleDefinition(
            id="PCI-6.5.1",
            control="PCI-A.6-INJECTION",
            title="SQL Injection Prevention",
            summary="Queries must use parameterized APIs.",
            rego_module="pcidss",
            rego_rule="sql_injection",
            severity="critical",
        )
        custom_pack = PolicyPackSpec(
            pack_id="pci-dss",
            name="PCI-DSS v4.0 Application Security Pack",
            standard="PCI-DSS",
            version="4.0.0",
            rego_dir=Path("/tmp/pci-dss"),
            query_entrypoints=("data.pcidss.violations",),
            rules=(rule,),
        )
        registry.register_pack(custom_pack)

        self.assertEqual(len(registry.list_packs()), 2)
        pci = registry.get_pack("pci-dss")
        self.assertIsNotNone(pci)
        assert pci is not None
        self.assertEqual(pci.name, "PCI-DSS v4.0 Application Security Pack")
        self.assertEqual(registry.get_rule("PCI-6.5.1"), rule)

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
