from __future__ import annotations

from collections.abc import Iterable

from codegraph.remediation.plugin_types import PluginDescriptor, RemediationShadowPlugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[tuple[str, str], RemediationShadowPlugin] = {}
        self._pattern_ids: set[tuple[str, str]] = set()

    def register(self, plugin: RemediationShadowPlugin) -> None:
        key = (plugin.descriptor.plugin_id, plugin.descriptor.plugin_version)
        if key in self._plugins:
            raise ValueError(f"Duplicate plugin registration: {plugin.descriptor.plugin_id}@{plugin.descriptor.plugin_version}")
        for pattern in plugin.descriptor.patterns:
            pattern_key = (pattern.pattern_id, pattern.pattern_version)
            if pattern_key in self._pattern_ids:
                raise ValueError(
                    f"Duplicate pattern registration: {pattern.pattern_id}@{pattern.pattern_version}"
                )
            self._pattern_ids.add(pattern_key)
        self._plugins[key] = plugin

    def all_descriptors(self) -> list[PluginDescriptor]:
        return [plugin.descriptor for plugin in self._ordered_plugins()]

    def resolve(self, *, rule_id: str, language: str) -> RemediationShadowPlugin | None:
        for plugin in self._ordered_plugins():
            if plugin.supports(rule_id=rule_id, language=language):
                return plugin
        return None

    def _ordered_plugins(self) -> list[RemediationShadowPlugin]:
        return [
            self._plugins[key]
            for key in sorted(
                self._plugins.keys(),
                key=lambda item: (item[0], item[1]),
            )
        ]


def build_registry(plugins: Iterable[RemediationShadowPlugin]) -> PluginRegistry:
    registry = PluginRegistry()
    for plugin in plugins:
        registry.register(plugin)
    return registry