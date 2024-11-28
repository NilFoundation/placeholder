import logging, json
from junitparser import JUnitXml
import glob, os
from opentelemetry import trace

aggregated_test_results = JUnitXml();
for file in glob.glob("result/test-logs/*_benchmark.xml"):
    try:
        test_result = JUnitXml.fromfile(file)
        result[test_result.name]=test_result.time
        aggregated_test_results.append(test_result)
    except Exception as ex:
        print("Error processing {}".format(file))
        print(ex)

for file in glob.glob("result/test-logs/*_benchmark.xml"):
    try:
    except Exception as ex:
        print("Error processing {}".format(file))
        print(ex)

succeeded = aggregated_test_results.tests - \
            aggregated_test_results.failures - \
            aggregated_test_results.errors - \
            aggregated_test_results.skipped

result = {
    "benchmark_tests"          : aggregated_test_results.tests,
    "benchmark_failures"       : aggregated_test_results.failures,
    "benchmark_errors"         : aggregated_test_results.errors,
    "benchmark_skipped"        : aggregated_test_results.skipped,
    "benchmark_succeeded"      : succeeded,
    "benchmark_execution_time" : aggregated_test_results.time,
}

print("Resulting JSON: {}".format(json.dumps(result)))

tracer = trace.get_tracer_provider().get_tracer(__name__)
with tracer.start_as_current_span("nightly_span"):
    current_span = trace.get_current_span()
    current_span.add_event("Nightly benchmarks build finished")
    logging.getLogger().error(json.dumps(result))

