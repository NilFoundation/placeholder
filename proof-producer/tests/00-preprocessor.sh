#!/bin/sh


if [ "x$1" = "x" ] ; then
    echo "Circuit not defined"
    exit 1
fi

CIRCUIT=$1

echo "Preprocessing circuit: [1;31m$CIRCUIT[0m"

bin/proof-producer/proof-producer \
    --circuit           circuits-and-assignments/$CIRCUIT/circuit.crct \
    --assignment-table  circuits-and-assignments/$CIRCUIT/assignment.tbl \
    --common-data $CIRCUIT-common_data.dat \
    --preprocessed-data $CIRCUIT-preprocessed.dat \
    --commitment-state-file $CIRCUIT-commitment_state.dat \
    --assignment-description-file $CIRCUIT-assignment-description.dat \
    --stage preprocess \
    --max-quotient-chunks 10

