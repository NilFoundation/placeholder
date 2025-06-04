#!/bin/sh

if [ "x$1" = "x" ] ; then
    echo "Circuit not defined"
    exit 1
fi

if [ "x$2" = "x" ] ; then
    echo "Starting power not defined"
    exit 1
fi


CIRCUIT=$1

echo "Computing combined Q for circuit: [1;31m$CIRCUIT[0m, starting power: $2"

bin/proof-producer/proof-producer \
    --stage compute-combined-Q  \
    --aggregated-challenge-file           "challenge-aggregated.dat" \
    --combined-Q-starting-power=$2  \
    --commitment-state-file               $CIRCUIT-commitment_state.dat \
    --combined-Q-polynomial-file          $CIRCUIT-combined-Q.dat


