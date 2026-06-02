from __future__ import annotations

from codegraph.policy.source_analysis_core import DEFAULT_POLICY_ANALYZER


def analyze_policy_indicators(source_code: str) -> dict[str, bool]:
    return DEFAULT_POLICY_ANALYZER.analyze(source_code)


def analyze_crypto_indicators(source_code: str) -> dict[str, bool]:
    return analyze_policy_indicators(source_code)
