"""
Telemetry bootstrap for CodeGraph.

Initialises the OpenTelemetry SDK once per process and exposes a ``get_tracer``
helper used by every instrumented module.

Usage
-----
Call ``configure_telemetry()`` once at process startup (``app.py`` or the CLI
entry point).  Then acquire a tracer per module::

    from codegraph.telemetry import get_tracer
    tracer = get_tracer(__name__)

    with tracer.start_as_current_span("my.span") as span:
        span.set_attribute("key", "value")

Log correlation
---------------
Call ``install_log_correlation()`` immediately after ``basicConfig`` to inject
``otel_trace_id`` and ``otel_span_id`` into every log record.  When no span is
active both fields are the zero-value sentinel so the format string never
raises a ``KeyError``::

    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(otel_trace_id)s/%(otel_span_id)s] %(message)s",
    )
    install_log_correlation()

Export
------
By default spans are written to stdout via ``ConsoleSpanExporter``.

Set ``OTEL_TRACE_FILE=/path/to/traces.jsonl`` to write spans to a file instead
(one JSON object per line, safe for concurrent reads by the reporting script).

To export to a Grafana / Tempo / Jaeger collector set::

    OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

The exporter is swapped automatically — no code change required.

To silence all telemetry (e.g. in unit tests)::

    OTEL_SDK_DISABLED=true
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from opentelemetry import metrics, trace
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_initialized = False

# ── Log/trace correlation ─────────────────────────────────────────────────────


class OtelCorrelationFilter(logging.Filter):
    """Injects ``otel_trace_id`` and ``otel_span_id`` into every LogRecord.

    When no span is active (or telemetry is disabled) both fields are set to
    the zero-value sentinel so a format string like
    ``%(otel_trace_id)s/%(otel_span_id)s`` never raises a KeyError.
    """

    _ZERO_TRACE = "0" * 32
    _ZERO_SPAN = "0" * 16

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = trace.get_current_span().get_span_context()
        if ctx.is_valid:
            record.otel_trace_id = format(ctx.trace_id, "032x")
            record.otel_span_id = format(ctx.span_id, "016x")
        else:
            record.otel_trace_id = self._ZERO_TRACE
            record.otel_span_id = self._ZERO_SPAN
        return True


def install_log_correlation() -> None:
    """Attach :class:`OtelCorrelationFilter` to every handler on the root logger.

    Filters must be on *handlers*, not on the logger itself, because Python's
    propagation path calls ``handler.handle()`` directly and bypasses
    ``Logger.handle()`` — so logger-level filters are skipped for child-logger
    records that propagate up.

    Safe to call multiple times.  Safe when ``OTEL_SDK_DISABLED=true`` — the
    filter degrades to zero-value sentinels when no span is active.
    """
    root = logging.getLogger()
    _filter = OtelCorrelationFilter()
    for handler in root.handlers:
        if not any(isinstance(f, OtelCorrelationFilter) for f in handler.filters):
            handler.addFilter(_filter)


# ── Span file exporter ────────────────────────────────────────────────────────


class _FileSpanExporter:
    """Minimal span exporter that appends one JSON line per span to a file.

    Not a full ``SpanExporter`` subclass — wraps ``ConsoleSpanExporter`` and
    redirects its output to a file handle opened once at construction time.
    Using ConsoleSpanExporter's ``out`` parameter avoids re-implementing
    ``span.to_json()`` serialisation.
    """

    def __init__(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._fh = p.open("a", encoding="utf-8")
        # ConsoleSpanExporter accepts an ``out`` file-like; reuse its serialisation.
        self._inner = ConsoleSpanExporter(out=self._fh)

    # Mirror the SpanExporter interface used by BatchSpanProcessor.
    def export(self, spans):  # type: ignore[override]
        return self._inner.export(spans)

    def shutdown(self) -> None:
        self._inner.shutdown()
        self._fh.flush()
        self._fh.close()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        self._fh.flush()
        return True


# ── SDK bootstrap ─────────────────────────────────────────────────────────────


def configure_telemetry(service_name: str = "codegraph") -> None:
    """Initialise the OTel SDK.  Safe to call multiple times — only runs once."""
    global _initialized
    if _initialized:
        return
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() in ("1", "true", "yes"):
        _initialized = True
        return

    provider = TracerProvider()

    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    trace_file = os.environ.get("OTEL_TRACE_FILE")

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # noqa: PLC0415

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        except ImportError:
            exporter = ConsoleSpanExporter()  # type: ignore[assignment]
    elif trace_file:
        exporter = _FileSpanExporter(trace_file)  # type: ignore[assignment]
    else:
        exporter = ConsoleSpanExporter()  # type: ignore[assignment]

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    _configure_metrics(otlp_endpoint)

    # Auto-instrument outbound HTTP calls made by the OpenAI SDK (uses httpx).
    try:
        HTTPXClientInstrumentor().instrument()
    except Exception:  # pragma: no cover - optional extra
        pass

    _initialized = True


def _configure_metrics(otlp_endpoint: str | None) -> None:
    """Install a meter provider so usage metrics have somewhere to go.

    Metrics are opt-in for export: without an OTLP endpoint or an explicit
    console request, a provider with no reader is installed so instruments work
    and the in-process ledger still fills, without printing on every call.
    """
    readers = []
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (  # noqa: PLC0415
                OTLPMetricExporter,
            )

            readers.append(PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True)))
        except ImportError:
            logging.getLogger(__name__).debug("OTLP metric exporter unavailable; usage metrics stay in-process")
    elif os.environ.get("OTEL_METRICS_CONSOLE", "").lower() in ("1", "true", "yes"):
        readers.append(PeriodicExportingMetricReader(ConsoleMetricExporter()))

    metrics.set_meter_provider(MeterProvider(metric_readers=readers))


def get_meter(name: str) -> metrics.Meter:
    """Return a named meter.  Call ``configure_telemetry`` first."""
    return metrics.get_meter(name)


def get_tracer(name: str) -> trace.Tracer:
    """Return a named tracer.  Call ``configure_telemetry`` first."""
    return trace.get_tracer(name)
