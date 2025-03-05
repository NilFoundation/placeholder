import socket
import os
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.metrics.export import MetricExportResult

def post_results(result_set):
    hostname = socket.gethostname()

    # Configure the OTLP exporter
    OTLP_EXPORTER = os.environ.get("OTLP_ENDPOINT")
    if OTLP_EXPORTER is None:
        raise ValueError("OTLP_ENDPOINT environment variable is not set")
    otlp_exporter = OTLPMetricExporter(endpoint=OTLP_EXPORTER, insecure=True)

    resource = Resource.create({ "service.name": "proof-producer-benchmarks", "host.name": hostname })
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader], resource=resource)
    metrics.set_meter_provider(meter_provider)
    meter = metrics.get_meter("proof-producer-benchmarks")

    benchmark_gauge = meter.create_gauge(
        "benchmark_results",
        description="proof-producer benchmark results"
    )

    for result in result_set:
        benchmark_gauge.set(result["time"], {"benchmark": result["name"]})


    result = otlp_exporter.export(reader.get_metrics_data())
    if result != MetricExportResult.SUCCESS:
        raise RuntimeError("Failed to export metrics")
