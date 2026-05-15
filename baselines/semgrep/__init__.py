"""SemGrep comparative baseline for the LexicalNoiseJava benchmark.

This baseline lets us measure F10 against an AST-based SAST tool (SemGrep)
on the same fixtures the CodeGraph Rego rules are evaluated on. The
8 hand-written rules under ``rules/`` mirror the 8 active CWE families
in CodeGraph's policy catalog, so the comparison is rule-for-rule.
"""

from baselines.semgrep.runner import (
    SemgrepFinding,
    SemgrepRunResult,
    run_semgrep_baseline,
)

__all__ = [
    "SemgrepFinding",
    "SemgrepRunResult",
    "run_semgrep_baseline",
]
