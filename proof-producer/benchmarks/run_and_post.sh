#!/usr/bin/env bash

set -euxo pipefail

BENCHMARKS_DIR=`dirname "$0"`
# TODO: add invocation for different modes and posting results into signoz
python3 $BENCHMARKS_DIR/main.py --proof-producer-binary `command -v proof-producer-multi-threaded`
