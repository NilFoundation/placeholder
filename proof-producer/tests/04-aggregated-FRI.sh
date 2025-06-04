#!/bin/sh

CIRCUIT1=fri_array_swap
CIRCUIT2=merkle_tree_poseidon_cpp_example

echo "Computing aggregated FRI"

bin/proof-producer/proof-producer \
    --stage aggregated-FRI  \
    --assignment-description-file $CIRCUIT1-assignment-description.dat \
    --aggregated-challenge-file "challenge-aggregated.dat" \
    --input-combined-Q-polynomial-files "$CIRCUIT1-combined-Q.dat" \
    --input-combined-Q-polynomial-files "$CIRCUIT2-combined-Q.dat" \
    --proof="aggregated_FRI_proof.bin" \
    --proof-of-work-file="POW.dat" \
    --consistency-checks-challenges-file="challenges.dat"


