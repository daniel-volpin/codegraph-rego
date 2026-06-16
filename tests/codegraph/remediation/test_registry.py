from __future__ import annotations

import unittest

from codegraph.remediation.plugin_types import PluginDescriptor, PluginProposal, RepairPatternContract
from codegraph.remediation.registry import PluginRegistry
from codegraph.remediation.result_models import ArtifactKind, Disposition, TransformationStrategy


class _FakePlugin:
    def __init__(self, plugin_id: str, plugin_version: str, rule_id: str, pattern_id: str = "p1") -> None:
        self.descriptor = PluginDescriptor(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            supported_languages=["java"],
            supported_rule_ids=[rule_id],
            patterns=[
                RepairPatternContract(
                    pattern_id=pattern_id,
                    pattern_version="1.0.0",
                    transformation_strategy=TransformationStrategy.TYPED_STRUCTURED_EDITS,
                    max_edit_scope_lines=1,
                )
            ],
        )

    def supports(self, *, rule_id: str, language: str) -> bool:
        return rule_id in self.descriptor.supported_rule_ids and language in self.descriptor.supported_languages

    def propose(self, context: dict[str, object]) -> PluginProposal:
        return PluginProposal(artifact_kind=ArtifactKind.NONE, disposition=Disposition.ABSTAIN)

    def evaluate_semantics(self, *, context: dict[str, object], proposal: PluginProposal, updated_method_source: str | None):
        return []


class PluginRegistryTests(unittest.TestCase):
    def test_register_and_lookup_plugin(self) -> None:
        registry = PluginRegistry()
        plugin = _FakePlugin("sql", "1.0.0", "ISO-A.8-SQL-INJECTION")
        registry.register(plugin)

        resolved = registry.resolve(rule_id="ISO-A.8-SQL-INJECTION", language="java")

        self.assertIs(resolved, plugin)

    def test_no_compatible_plugin_returns_none(self) -> None:
        registry = PluginRegistry()
        registry.register(_FakePlugin("sql", "1.0.0", "ISO-A.8-SQL-INJECTION"))

        resolved = registry.resolve(rule_id="ISO-A.10-WEAK-HASH", language="java")

        self.assertIsNone(resolved)

    def test_duplicate_plugin_rejected(self) -> None:
        registry = PluginRegistry()
        registry.register(_FakePlugin("sql", "1.0.0", "ISO-A.8-SQL-INJECTION"))

        with self.assertRaises(ValueError):
            registry.register(_FakePlugin("sql", "1.0.0", "ISO-A.8-SQL-INJECTION"))

    def test_duplicate_pattern_rejected(self) -> None:
        registry = PluginRegistry()
        registry.register(_FakePlugin("sql", "1.0.0", "ISO-A.8-SQL-INJECTION", pattern_id="dup"))

        with self.assertRaises(ValueError):
            registry.register(_FakePlugin("sql-other", "1.0.0", "ISO-A.8-SQL-INJECTION", pattern_id="dup"))

    def test_lookup_is_deterministic_by_plugin_id_and_version(self) -> None:
        registry = PluginRegistry()
        later = _FakePlugin("z-plugin", "1.0.0", "ISO-A.8-SQL-INJECTION", pattern_id="p2")
        earlier = _FakePlugin("a-plugin", "2.0.0", "ISO-A.8-SQL-INJECTION", pattern_id="p1")
        registry.register(later)
        registry.register(earlier)

        resolved = registry.resolve(rule_id="ISO-A.8-SQL-INJECTION", language="java")

        self.assertIs(resolved, earlier)


if __name__ == "__main__":
    unittest.main()