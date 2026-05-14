"""Loader for the LexicalNoiseJava benchmark.

The benchmark is a small (~30 case) hand-curated set of Java methods
stratified by lexical-FP source type (line comment, block comment,
string literal, char literal, text block). Each case is labelled with
the violation it targets and an ``expected`` polarity:

* ``negative`` — the noise alone must not trigger a violation.
* ``positive`` — the active code legitimately matches the rule even
  with noise present, so a correctly-anchored detector must still fire.

This module loads the manifest (a JSON file under ``configs/benchmark/``)
and exposes a typed, frozen view of the benchmark for downstream
evaluation scripts. It performs no Java parsing, no Neo4j or OPA
interaction — only manifest validation. The actual detection-eval
runner that consumes this loader lives in Phase D.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


VALID_FP_SOURCES: frozenset[str] = frozenset(
    {"line_comment", "block_comment", "string_literal", "char_literal", "text_block"}
)
VALID_EXPECTATIONS: frozenset[str] = frozenset({"negative", "positive"})


@dataclass(frozen=True)
class LexicalNoiseCase:
    case_id: str
    file_name: str
    fp_source: str
    expected: str
    target_violation_ids: Tuple[str, ...]
    tokens_in_noise: Tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        if self.fp_source not in VALID_FP_SOURCES:
            raise ValueError(
                f"case {self.case_id}: fp_source '{self.fp_source}' not in {sorted(VALID_FP_SOURCES)}"
            )
        if self.expected not in VALID_EXPECTATIONS:
            raise ValueError(
                f"case {self.case_id}: expected '{self.expected}' not in {sorted(VALID_EXPECTATIONS)}"
            )
        if not self.target_violation_ids:
            raise ValueError(f"case {self.case_id}: target_violation_ids must be non-empty")


@dataclass(frozen=True)
class LexicalNoiseBenchmark:
    benchmark_id: str
    version: int
    description: str
    fixture_root_relative: str
    java_relative_root: str
    package: str
    cases: Tuple[LexicalNoiseCase, ...]

    def resolve_fixture_root(self, project_root: Path) -> Path:
        return project_root / self.fixture_root_relative

    def resolve_java_root(self, project_root: Path) -> Path:
        return self.resolve_fixture_root(project_root) / self.java_relative_root

    def negatives(self) -> Tuple[LexicalNoiseCase, ...]:
        return tuple(case for case in self.cases if case.expected == "negative")

    def positives(self) -> Tuple[LexicalNoiseCase, ...]:
        return tuple(case for case in self.cases if case.expected == "positive")

    def by_fp_source(self, fp_source: str) -> Tuple[LexicalNoiseCase, ...]:
        return tuple(case for case in self.cases if case.fp_source == fp_source)


def load_lexical_noise_manifest(path: str | Path) -> LexicalNoiseBenchmark:
    """Parse and validate the manifest JSON, returning a frozen benchmark.

    Raises ``FileNotFoundError`` when the manifest is missing,
    ``ValueError`` when required fields are absent or invalid.
    """
    manifest_path = Path(path)
    with manifest_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    required_keys = (
        "benchmark_id",
        "version",
        "description",
        "fixture_root_relative",
        "java_relative_root",
        "package",
        "cases",
    )
    for key in required_keys:
        if key not in payload:
            raise ValueError(f"lexical_noise manifest at {path!s}: missing required key '{key}'")

    raw_cases = payload["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"lexical_noise manifest at {path!s}: 'cases' must be a non-empty list")

    case_ids: set[str] = set()
    cases: list[LexicalNoiseCase] = []
    for entry in raw_cases:
        if not isinstance(entry, dict):
            raise ValueError(f"lexical_noise manifest at {path!s}: case entries must be objects")
        case_id = str(entry.get("case_id") or "").strip()
        if not case_id:
            raise ValueError(f"lexical_noise manifest at {path!s}: case missing case_id")
        if case_id in case_ids:
            raise ValueError(f"lexical_noise manifest at {path!s}: duplicate case_id '{case_id}'")
        case_ids.add(case_id)
        cases.append(
            LexicalNoiseCase(
                case_id=case_id,
                file_name=str(entry.get("file_name") or "").strip(),
                fp_source=str(entry.get("fp_source") or "").strip(),
                expected=str(entry.get("expected") or "").strip(),
                target_violation_ids=tuple(str(v) for v in (entry.get("target_violation_ids") or [])),
                tokens_in_noise=tuple(str(t) for t in (entry.get("tokens_in_noise") or [])),
                rationale=str(entry.get("rationale") or "").strip(),
            )
        )

    return LexicalNoiseBenchmark(
        benchmark_id=str(payload["benchmark_id"]),
        version=int(payload["version"]),
        description=str(payload["description"]),
        fixture_root_relative=str(payload["fixture_root_relative"]),
        java_relative_root=str(payload["java_relative_root"]),
        package=str(payload["package"]),
        cases=tuple(cases),
    )
