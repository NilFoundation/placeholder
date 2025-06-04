#!/usr/bin/env bash

set -euxo pipefail

BENCHMARKS_DIR=`dirname "$0"`
python3 -m venv $BENCHMARKS_DIR/env
source $BENCHMARKS_DIR/env/bin/activate
pip install -r $BENCHMARKS_DIR/requirements.txt
systemd-run --scope --slice=benchexec -p Delegate=yes \
    python3 $BENCHMARKS_DIR/main.py \
        --proof-producer-binary /usr/bin/proof-producer \
        --trace $BENCHMARKS_DIR/traces/hundred_plus_hundred_trace \
        --execution_mode subprocess \
        --scenario full \
        --post-results
