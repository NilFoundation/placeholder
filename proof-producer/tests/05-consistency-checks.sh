#!/bin/sh

if [ "x$1" = "x" ] ; then
    echo "Circuit not defined"
    exit 1
fi

CIRCUIT=$1

echo "Consistency chacks for circuit: [1;31m$CIRCUIT[0m"

bin/proof-producer/proof-producer \
    --stage consistency-checks  \
    --commitment-state-file $CIRCUIT-updated_commitment_state.dat \
    --combined-Q-polynomial-file $CIRCUIT-combined-Q.dat \
    --consistency-checks-challenges-file "challenges.dat" \
    --proof $CIRCUIT-LPC_consistency_check_proof.bin
