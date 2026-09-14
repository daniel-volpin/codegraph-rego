"""Benchmark-root resolution must not require manual environment setup.

The OWASP corpus is a separate clone, so the evaluation scripts have to work
for someone who follows the README literally. Equally, an unresolvable root
must fail with a clear cause rather than a path containing a literal
``${VAR}``, which surfaces much later as a confusing missing-directory error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codegraph.evaluation import benchmark


@pytest.fixture
def fake_checkout(tmp_path: Path) -> Path:
    root = tmp_path / "BenchmarkJava"
    (root / "src" / "main" / "java").mkdir(parents=True)
    (root / "expectedresults-1.2.csv").write_text("# test name, category\n", encoding="utf-8")
    return root


@pytest.fixture
def selection_config(tmp_path: Path) -> Path:
    path = tmp_path / "selection.json"
    path.write_text(
        json.dumps(
            {
                "benchmark_root": "${OWASP_BENCHMARK_ROOT}",
                "ground_truth_path": "${OWASP_BENCHMARK_ROOT}/expectedresults-1.2.csv",
                "categories": ["hash-md5"],
            }
        ),
        encoding="utf-8",
    )
    return path


class TestDiscovery:
    def test_finds_the_in_repo_checkout_when_unset(self, monkeypatch, fake_checkout: Path) -> None:
        monkeypatch.delenv(benchmark._BENCHMARK_ROOT_VAR, raising=False)
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", fake_checkout.parent)
        assert benchmark.ensure_benchmark_root_env() == str(fake_checkout)

    def test_a_sibling_checkout_is_no_longer_discovered(self, monkeypatch, fake_checkout: Path) -> None:
        """One default location only: a sibling needs OWASP_BENCHMARK_ROOT."""
        monkeypatch.delenv(benchmark._BENCHMARK_ROOT_VAR, raising=False)
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", fake_checkout.parent / "codegraph")
        assert benchmark.ensure_benchmark_root_env() is None

    def test_explicit_configuration_wins_over_discovery(self, monkeypatch, fake_checkout: Path) -> None:
        monkeypatch.setenv(benchmark._BENCHMARK_ROOT_VAR, "/explicit/path")
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", fake_checkout.parent)
        assert benchmark.ensure_benchmark_root_env() == "/explicit/path"

    def test_a_directory_without_ground_truth_is_not_the_corpus(self, monkeypatch, tmp_path: Path) -> None:
        """Identified by its ground-truth file, so a same-named directory is not mistaken for it."""
        decoy = tmp_path / "BenchmarkJava"
        decoy.mkdir()
        monkeypatch.delenv(benchmark._BENCHMARK_ROOT_VAR, raising=False)
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", tmp_path / "codegraph")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "nohome"))
        assert benchmark.ensure_benchmark_root_env() is None


class TestFailureIsActionable:
    def test_unresolvable_root_raises_with_guidance(self, monkeypatch, tmp_path: Path, selection_config: Path) -> None:
        monkeypatch.delenv(benchmark._BENCHMARK_ROOT_VAR, raising=False)
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", tmp_path / "codegraph")
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "nohome"))
        with pytest.raises(ValueError, match="OWASP_BENCHMARK_ROOT is not set"):
            benchmark.load_selection_config(selection_config)

    def test_resolved_config_contains_no_literal_variable(
        self, monkeypatch, fake_checkout: Path, selection_config: Path
    ) -> None:
        monkeypatch.delenv(benchmark._BENCHMARK_ROOT_VAR, raising=False)
        monkeypatch.setattr(benchmark, "_PROJECT_ROOT", fake_checkout.parent)
        cfg = benchmark.load_selection_config(selection_config)
        assert cfg["benchmark_root"] == str(fake_checkout)
        assert "$" not in cfg["benchmark_root"]
        assert "$" not in cfg["ground_truth_path"]
