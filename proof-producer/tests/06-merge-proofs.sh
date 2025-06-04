#!/bin/sh

CIRCUIT1=fri_array_swap
CIRCUIT2=merkle_tree_poseidon_cpp_example

echo "Merging proofs"

bin/proof-producer/proof-producer \
    --stage merge-proofs  \
    --partial-proof $CIRCUIT1-proof.dat \
    --partial-proof $CIRCUIT2-proof.dat \
    --initial-proof $CIRCUIT1-LPC_consistency_check_proof.bin \
    --initial-proof $CIRCUIT2-LPC_consistency_check_proof.bin \
    --aggregated-FRI-proof aggregated_FRI_proof.bin \
    --proof final-proof.dat




