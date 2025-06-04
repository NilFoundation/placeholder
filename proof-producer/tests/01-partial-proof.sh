#!/bin/sh

if [ "x$1" = "x" ] ; then
    echo "Circuit not defined"
    exit 1
fi

CIRCUIT=$1

echo "Partial proof for circuit: [1;31m$CIRCUIT[0m"

bin/proof-producer/proof-producer \
    --stage generate-partial-proof \
    --max-quotient-chunks 10 \
    --circuit           circuits-and-assignments/$CIRCUIT/circuit.crct \
    --assignment-table  circuits-and-assignments/$CIRCUIT/assignment.tbl \
    --common-data                  $CIRCUIT-common_data.dat \
    --preprocessed-data            $CIRCUIT-preprocessed.dat \
    --commitment-state-file        $CIRCUIT-commitment_state.dat \
    --updated-commitment-state-file $CIRCUIT-updated_commitment_state.dat \
    --assignment-description-file  $CIRCUIT-assignment-description.dat \
    --challenge-file               $CIRCUIT-challenge.dat \
    --theta-power-file             $CIRCUIT-theta-power.txt \
    --proof                        $CIRCUIT-proof.dat \
    --json                         $CIRCUIT-proof.json

