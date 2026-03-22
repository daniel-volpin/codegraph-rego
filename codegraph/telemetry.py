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

Export
------
By default spans are written to stdout via ``ConsoleSpanExporter`` (ideal for
redirecting to a per-run log file during benchmarks).

To export to a Grafana / Tempo / Jaeger collector set the standard env var::

    OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

The exporter is swapped automatically — no code change required.

To silence all telemetry (e.g. in unit tests)::

    OTEL_SDK_DISABLED=true
"""

from __future__ import annotations

import os

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_initialized = False


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
    if otlp_endpoint:
        # Lazy import so the grpc dependency is only required when actually exporting.
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # noqa: PLC0415

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        except ImportError:
            # Fall back to console if the grpc extra is not installed.
            exporter = ConsoleSpanExporter()  # type: ignore[assignment]
    else:
        exporter = ConsoleSpanExporter()  # type: ignore[assignment]

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Auto-instrument outbound HTTP calls made by the OpenAI SDK (uses httpx).
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # noqa: PLC0415

        HTTPXClientInstrumentor().instrument()
    except Exception:  # pragma: no cover - optional extra
        pass

    _initialized = True


def get_tracer(name: str) -> trace.Tracer:
    """Return a named tracer.  Call ``configure_telemetry`` first."""
    return trace.get_tracer(name)
