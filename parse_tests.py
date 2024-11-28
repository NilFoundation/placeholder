import logging, json
from junitparser import JUnitXml
import glob, os
from opentelemetry import trace

undefined_behavior_sanitizer=os.environ['UndefinedBehaviorSanitizer']
address_sanitizer=os.environ['AddressSanitizer']
leak_sanitizer=os.environ['LeakSanitizer']

aggregated_test_results = JUnitXml();
for file in glob.glob("result/test-logs/*.xml"):
    try:
        aggregated_test_results.append(JUnitXml.fromfile(file))
    except Exception as ex:
        print("Error processing {}".format(file))
        print(ex)

succeeded = aggregated_test_results.tests - \
            aggregated_test_results.failures - \
            aggregated_test_results.errors - \
            aggregated_test_results.skipped

result = {
    "tests"          : aggregated_test_results.tests,
    "failures"       : aggregated_test_results.failures,
    "errors"         : aggregated_test_results.errors,
    "skipped"        : aggregated_test_results.skipped,
    "succeeded"      : succeeded,
    "execution_time"               : aggregated_test_results.time,
    "undefined_behavior_sanitizer" : int(undefined_behavior_sanitizer),
    "address_sanitizer"            : int(address_sanitizer),
    "leak_sanitizer"               : int(leak_sanitizer),
}

print("Resulting JSON: {}".format(json.dumps(result)))

tracer = trace.get_tracer_provider().get_tracer(__name__)
with tracer.start_as_current_span("nightly_span"):
    current_span = trace.get_current_span()
    current_span.add_event("Nightly build finished")
    logging.getLogger().error(json.dumps(result))

