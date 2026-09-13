"""Model consumption accounting for every LLM provider the framework calls.

Consumption was previously visible only as span attributes, so it vanished
unless a trace collector happened to be running, and no evaluation artifact
could report what a run cost. This module records consumption twice: as
OpenTelemetry metrics for whoever collects them, and in a process-local ledger
an evaluation can snapshot into its own artifact.

Instrument and attribute names follow the OpenTelemetry GenAI semantic
conventions (``gen_ai.client.token.usage`` partitioned by ``gen_ai.token.type``,
``gen_ai.client.operation.duration``). Those conventions are still in
Development upstream and a migration to counters named
``gen_ai.client.inference.tokens`` is proposed, so treat the metric names as
liable to change; the ledger below does not depend on them.

Rates are configuration, never defaults baked into the source. An unpriced
model reports units with ``estimated_cost_usd`` absent rather than a number
invented here, because a wrong cost is worse than no cost.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from codegraph.config import settings
from codegraph.telemetry import get_meter

LOGGER = logging.getLogger(__name__)

_UNITS_PER_PRICED_BLOCK = 1_000_000

# Recommended by the GenAI metrics convention for token-magnitude histograms.
_USAGE_BUCKET_BOUNDARIES = [
    1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144,
    1048576, 4194304, 16777216, 67108864,
]

_lock = threading.Lock()
_ledger: dict[tuple[str, str], _ModelUsage] = {}

_meter = None
_usage_histogram = None
_duration_histogram = None


@dataclass
class _ModelUsage:
    provider: str
    model: str
    calls: int = 0
    input_units: int = 0
    output_units: int = 0
    cached_input_units: int = 0
    reasoning_output_units: int = 0
    unreported_usage_calls: int = 0
    duration_seconds: float = 0.0
    task_types: set[str] = field(default_factory=set)


def _instruments() -> None:
    """Create metric instruments once, tolerating an unconfigured meter."""
    global _meter, _usage_histogram, _duration_histogram
    if _meter is not None:
        return
    try:
        _meter = get_meter(__name__)
        _usage_histogram = _meter.create_histogram(
            "gen_ai.client.token.usage",
            unit="{token}",
            description="Number of input and output tokens used",
            explicit_bucket_boundaries_advisory=_USAGE_BUCKET_BOUNDARIES,
        )
        _duration_histogram = _meter.create_histogram(
            "gen_ai.client.operation.duration",
            unit="s",
            description="GenAI operation duration",
        )
    except TypeError:
        # Older SDKs reject the bucket advisory; the metric still matters more
        # than its bucketing.
        _usage_histogram = _meter.create_histogram(
            "gen_ai.client.token.usage", unit="{token}", description="Number of input and output tokens used"
        )
        _duration_histogram = _meter.create_histogram(
            "gen_ai.client.operation.duration", unit="s", description="GenAI operation duration"
        )
    except Exception as exc:  # pragma: no cover - telemetry must never break a call
        LOGGER.debug("Model usage metrics unavailable: %s", exc)


def _model_rates(model: str) -> dict[str, float] | None:
    rates = settings.llm_price_per_million or {}
    entry = rates.get(model)
    if not entry:
        return None
    try:
        resolved = {"input": float(entry["input"]), "output": float(entry["output"])}
    except (KeyError, TypeError, ValueError):
        LOGGER.warning("Ignoring malformed price entry for %s; expected input and output rates", model)
        return None
    cached = entry.get("cached_input")
    if cached is not None:
        try:
            resolved["cached_input"] = float(cached)
        except (TypeError, ValueError):
            LOGGER.warning("Ignoring malformed cached_input rate for %s", model)
    return resolved


def record_llm_usage(
    *,
    provider: str,
    model: str,
    task_type: str,
    input_units: int,
    output_units: int,
    cached_input_units: int = 0,
    reasoning_output_units: int = 0,
    duration_seconds: float | None = None,
) -> None:
    """Record one model call.

    ``input_units``/``output_units`` accept the transport's -1 for "the provider
    reported nothing", which is counted separately so a snapshot can say how
    much of a run is unaccounted rather than implying zero consumption.

    ``reasoning_output_units`` is already part of ``output_units`` upstream and
    is kept only for visibility; it is never added to the totals.
    """
    _instruments()
    attributes = {
        "gen_ai.provider.name": provider,
        "gen_ai.request.model": model,
        "gen_ai.operation.name": task_type,
    }
    reported = input_units >= 0 or output_units >= 0

    try:
        if _usage_histogram is not None:
            if input_units > 0:
                _usage_histogram.record(input_units, {**attributes, "gen_ai.token.type": "input"})
            if output_units > 0:
                _usage_histogram.record(output_units, {**attributes, "gen_ai.token.type": "output"})
        if _duration_histogram is not None and duration_seconds is not None:
            _duration_histogram.record(duration_seconds, attributes)
    except Exception as exc:  # pragma: no cover
        LOGGER.debug("Could not emit model usage metrics: %s", exc)

    with _lock:
        entry = _ledger.setdefault((provider, model), _ModelUsage(provider=provider, model=model))
        entry.calls += 1
        entry.input_units += max(0, input_units)
        entry.output_units += max(0, output_units)
        entry.cached_input_units += max(0, cached_input_units)
        entry.reasoning_output_units += max(0, reasoning_output_units)
        entry.duration_seconds += duration_seconds or 0.0
        entry.task_types.add(task_type)
        if not reported:
            entry.unreported_usage_calls += 1


def _estimate_cost(entry: _ModelUsage, rates: dict[str, float]) -> float:
    """Cost in USD, charging cached input at its own rate when one is configured.

    Without a configured cached rate the cached portion is charged at the full
    input rate. That overstates rather than understates, and avoids inventing a
    discount that belongs to a provider's price list, not to this code.
    """
    cached = min(entry.cached_input_units, entry.input_units)
    uncached = entry.input_units - cached
    cached_rate = rates.get("cached_input", rates["input"])
    units = uncached * rates["input"] + cached * cached_rate + entry.output_units * rates["output"]
    return units / _UNITS_PER_PRICED_BLOCK


def usage_snapshot() -> dict[str, Any]:
    """Consumption so far, shaped for an evaluation artifact."""
    with _lock:
        entries = [
            _ModelUsage(
                provider=entry.provider,
                model=entry.model,
                calls=entry.calls,
                input_units=entry.input_units,
                output_units=entry.output_units,
                cached_input_units=entry.cached_input_units,
                reasoning_output_units=entry.reasoning_output_units,
                unreported_usage_calls=entry.unreported_usage_calls,
                duration_seconds=entry.duration_seconds,
                task_types=set(entry.task_types),
            )
            for entry in _ledger.values()
        ]

    by_model: list[dict[str, Any]] = []
    total_cost = 0.0
    priced_models = 0
    for entry in sorted(entries, key=lambda item: (item.provider, item.model)):
        record: dict[str, Any] = {
            "provider": entry.provider,
            "model": entry.model,
            "calls": entry.calls,
            "input_units": entry.input_units,
            "output_units": entry.output_units,
            "task_types": sorted(entry.task_types),
            "duration_seconds": round(entry.duration_seconds, 3),
        }
        if entry.cached_input_units:
            record["cached_input_units"] = entry.cached_input_units
        if entry.reasoning_output_units:
            # Part of output_units already; reported for visibility only.
            record["reasoning_output_units"] = entry.reasoning_output_units
        if entry.unreported_usage_calls:
            record["calls_without_reported_usage"] = entry.unreported_usage_calls
        rates = _model_rates(entry.model)
        if rates is not None:
            cost = _estimate_cost(entry, rates)
            record["estimated_cost_usd"] = round(cost, 6)
            if entry.cached_input_units and "cached_input" not in rates:
                record["cost_note"] = "cached input charged at the full input rate; no cached_input rate configured"
            total_cost += cost
            priced_models += 1
        by_model.append(record)

    snapshot: dict[str, Any] = {
        "by_model": by_model,
        "calls": sum(entry.calls for entry in entries),
        "input_units": sum(entry.input_units for entry in entries),
        "output_units": sum(entry.output_units for entry in entries),
    }
    unpriced = [record["model"] for record in by_model if "estimated_cost_usd" not in record]
    if priced_models:
        snapshot["estimated_cost_usd"] = round(total_cost, 6)
    if unpriced:
        # Named explicitly so a partial total is never mistaken for a full one.
        snapshot["unpriced_models"] = unpriced
    return snapshot


def reset_usage() -> None:
    """Clear the ledger so a run reports only its own consumption."""
    with _lock:
        _ledger.clear()
