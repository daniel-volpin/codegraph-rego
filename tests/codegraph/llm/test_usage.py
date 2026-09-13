"""Model consumption accounting must never invent a number.

A run's reported cost becomes evidence, so the ledger has to distinguish three
different things that all used to look like zero: a model that consumed
nothing, a model whose rate is not configured, and a call the provider
reported no usage for.
"""

from __future__ import annotations

import pytest

from codegraph.llm import usage as usage_module


@pytest.fixture(autouse=True)
def _clean_ledger():
    usage_module.reset_usage()
    yield
    usage_module.reset_usage()


@pytest.fixture
def priced(monkeypatch):
    class _Settings:
        llm_price_per_million = {"gpt-5.4": {"input": 1.25, "output": 10.0}}

    monkeypatch.setattr(usage_module, "settings", _Settings())


def _record(**overrides):
    payload = {
        "provider": "openai",
        "model": "gpt-5.4",
        "task_type": "remediation",
        "input_units": 1_000_000,
        "output_units": 100_000,
    }
    payload.update(overrides)
    usage_module.record_llm_usage(**payload)


class TestAccounting:
    def test_units_accumulate_per_model(self) -> None:
        _record(input_units=10, output_units=5)
        _record(input_units=20, output_units=7)
        snapshot = usage_module.usage_snapshot()
        assert snapshot["calls"] == 2
        assert snapshot["input_units"] == 30
        assert snapshot["output_units"] == 12

    def test_providers_are_kept_apart(self) -> None:
        """A hosted and a local model must not be pooled into one line."""
        _record(provider="openai", model="gpt-5.4", input_units=10, output_units=1)
        _record(provider="lmstudio", model="qwen3.5-9b-mlx", input_units=90, output_units=9)
        by_model = {(row["provider"], row["model"]) for row in usage_module.usage_snapshot()["by_model"]}
        assert by_model == {("openai", "gpt-5.4"), ("lmstudio", "qwen3.5-9b-mlx")}

    def test_reset_scopes_a_run(self) -> None:
        _record(input_units=10, output_units=1)
        usage_module.reset_usage()
        assert usage_module.usage_snapshot()["calls"] == 0


class TestCostIsOnlyReportedWhenKnown:
    def test_configured_rates_produce_a_cost(self, priced) -> None:
        _record(input_units=1_000_000, output_units=100_000)
        snapshot = usage_module.usage_snapshot()
        # 1.25 for a million input units, 10.0 for a million output units.
        assert snapshot["estimated_cost_usd"] == pytest.approx(1.25 + 1.0)
        assert "unpriced_models" not in snapshot

    def test_unpriced_model_reports_units_without_a_cost(self) -> None:
        _record(model="some-local-model", input_units=500, output_units=50)
        snapshot = usage_module.usage_snapshot()
        assert "estimated_cost_usd" not in snapshot["by_model"][0]
        assert snapshot["unpriced_models"] == ["some-local-model"]

    def test_partial_pricing_names_what_is_missing(self, priced) -> None:
        """A total covering only some models must say so, or it reads as complete."""
        _record(model="gpt-5.4", input_units=1_000_000, output_units=0)
        _record(provider="lmstudio", model="qwen3.5-9b-mlx", input_units=9_000, output_units=900)
        snapshot = usage_module.usage_snapshot()
        assert snapshot["estimated_cost_usd"] == pytest.approx(1.25)
        assert snapshot["unpriced_models"] == ["qwen3.5-9b-mlx"]

    def test_malformed_rate_entry_is_ignored_not_guessed(self, monkeypatch) -> None:
        class _Settings:
            llm_price_per_million = {"gpt-5.4": {"input": "not-a-number"}}

        monkeypatch.setattr(usage_module, "settings", _Settings())
        _record(input_units=1_000, output_units=100)
        assert "estimated_cost_usd" not in usage_module.usage_snapshot()["by_model"][0]


class TestUnreportedUsage:
    def test_calls_without_usage_are_counted_separately(self) -> None:
        """A provider that reports nothing must not look like zero consumption."""
        _record(input_units=-1, output_units=-1)
        row = usage_module.usage_snapshot()["by_model"][0]
        assert row["calls"] == 1
        assert row["input_units"] == 0
        assert row["calls_without_reported_usage"] == 1

    def test_reported_calls_carry_no_such_marker(self) -> None:
        _record(input_units=10, output_units=2)
        assert "calls_without_reported_usage" not in usage_module.usage_snapshot()["by_model"][0]

    def test_duration_and_task_types_are_retained(self) -> None:
        _record(task_type="remediation", duration_seconds=1.5)
        _record(task_type="explanation", duration_seconds=0.5)
        row = usage_module.usage_snapshot()["by_model"][0]
        assert row["task_types"] == ["explanation", "remediation"]
        assert row["duration_seconds"] == pytest.approx(2.0)


class TestCachedAndReasoningUnits:
    """Cached input is discounted upstream; reasoning output is already counted."""

    def test_cached_units_are_reported(self) -> None:
        _record(input_units=1000, output_units=100, cached_input_units=800)
        row = usage_module.usage_snapshot()["by_model"][0]
        assert row["cached_input_units"] == 800
        assert row["input_units"] == 1000

    def test_reasoning_units_are_visible_but_not_added(self) -> None:
        _record(input_units=100, output_units=500, reasoning_output_units=400)
        row = usage_module.usage_snapshot()["by_model"][0]
        assert row["output_units"] == 500
        assert row["reasoning_output_units"] == 400

    def test_cached_rate_reduces_the_estimate(self, monkeypatch) -> None:
        class _Settings:
            llm_price_per_million = {"m": {"input": 10.0, "output": 0.0, "cached_input": 1.0}}

        monkeypatch.setattr(usage_module, "settings", _Settings())
        _record(model="m", input_units=1_000_000, output_units=0, cached_input_units=900_000)
        snapshot = usage_module.usage_snapshot()
        # 100k uncached at 10.0/M, plus 900k cached at 1.0/M.
        assert snapshot["estimated_cost_usd"] == pytest.approx(1.0 + 0.9)

    def test_without_a_cached_rate_the_estimate_overstates_and_says_so(self, priced) -> None:
        _record(model="gpt-5.4", input_units=1_000_000, output_units=0, cached_input_units=900_000)
        row = usage_module.usage_snapshot()["by_model"][0]
        assert row["estimated_cost_usd"] == pytest.approx(1.25)
        assert "cached input charged at the full input rate" in row["cost_note"]

    def test_cached_units_cannot_exceed_input(self) -> None:
        """A provider over-reporting cached units must not produce a negative charge."""
        rates = {"input": 10.0, "output": 0.0, "cached_input": 0.0}
        _record(model="m", input_units=100, output_units=0, cached_input_units=10_000)
        entry = usage_module._ledger[("openai", "m")]
        cost = usage_module._estimate_cost(entry, rates)
        assert cost == pytest.approx(0.0)
        assert cost >= 0.0


if __name__ == "__main__":
    pytest.main([__file__])
