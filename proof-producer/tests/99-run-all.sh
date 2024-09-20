#!/bin/sh

# This suite expects that circuits are extracted into "circuits-and-assignments" directory
# You can get these from https://github.com/NilFoundation/zkLLVM/actions
# Pick latest pipeline run from master, scroll down to "Artifacts" section and
# download zip. The size (10Gb) is of unpacked data, downloaded archive is 100Mb or so.

CIRCUIT1=fri_array_swap
CIRCUIT2=merkle_tree_poseidon_cpp_example

echo "[33;1m === STAGE 00 === [0m"
./00-preprocessor.sh $CIRCUIT1
./00-preprocessor.sh $CIRCUIT2

echo "[33;1m === STAGE 01 === [0m"
./01-partial-proof.sh $CIRCUIT1
./01-partial-proof.sh $CIRCUIT2

echo "[33;1m === STAGE 02 === [0m"
./02-gen-challenges.sh

echo "[33;1m === STAGE 03 === [0m"
./03-compute-combined-Q.sh $CIRCUIT1 0
./03-compute-combined-Q.sh $CIRCUIT2 `cat $CIRCUIT1-theta-power.txt`

echo "[33;1m === STAGE 04 === [0m"
./04-aggregated-FRI.sh

echo "[33;1m === STAGE 05 === [0m"
./05-consistency-checks.sh $CIRCUIT1
./05-consistency-checks.sh $CIRCUIT2

echo "[33;1m === STAGE 06 === [0m"
./06-merge-proofs.sh



