#!/bin/sh

echo "Generating challenges"

bin/proof-producer/proof-producer \
    --stage generate-aggregated-challenge  \
    -u "fri_array_swap-challenge.dat" \
    -u "merkle_tree_poseidon_cpp_example-challenge.dat" \
    --aggregated-challenge-file "challenge-aggregated.dat"


