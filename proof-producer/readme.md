# Proof producer
Executable for generating and verifying zk proof.

## Contents
1. [Structure](#structure)
2. [How to use](#how_to_use)
3. [Building from source](#building_from_source)
4. [Sample calls to proof-producer](#sample_calls_to_proof-producer)

## Structure
proof-producer
├── bin
├── cmake
├── libs
└── tests

## How to use
The input for the proof producer is an EVM trace or a circuit plus an assignment table.

Typically, you want to use the proof producer to generate validity proof of blocks
processed on =nil; rollup.

The proof producer is a command line tool. To see the list of available
options, run:

```bash
proof-producer --help
```

## Building from source
To build an individual target:
```bash
nix build -L .#proof-producer
```

To build tests:
```bash
nix develop .#proof-producer-tests
eval "$configurePhase" // automatically move to the build directory
ninja <test target>
```


## Sample calls to proof-producer
In all the calls you can change the executable name from
proof-producer to run on all
the CPUs of your machine.

### Using proof-producer to generate and verify a single proof
Generate circuit:
```bash
./result/bin/proof-producer \
    --stage "preset" \
    --circuit-name "zkevm" \
    --circuit="circuit.crct"
```

Generate assignemnt table from EVM trace:
```bash
./result/bin/proof-producer \
    --stage "fill-assignment" \
    --circuit-name "zkevm" \
    --trace "trace.pb" \
    --assignment-table="assignment.tbl" \
    --assignment-description-file="assignment-description.dat"
```

Generate a proof and verify it:
```bash
./result/bin/proof-producer \
    --circuit="circuit.crct" \
    --assignment-table="assignment.tbl" \
    --proof="proof.bin" -q 10
```

Making a call to preprocessor:

```bash
./result/bin/proof-producer \
    --stage="preprocess" \
    --circuit="circuit.crct" \
    --assignment-table="assignment.tbl" \
    --common-data="preprocessed_common_data.dat" \
    --preprocessed-data="preprocessed.dat" \
    --commitment-state-file="commitment_state.dat" \
    --assignment-description-file="assignment-description.dat" \
    -q 10
```

Making a call to prover:

```bash
./result/bin/proof-producer \
    --stage="prove" \
    --circuit="circuit.crct" \
    --assignment-table="assignment.tbl" \
    --common-data="preprocessed_common_data.dat" \
    --preprocessed-data="preprocessed.dat" \
    --commitment-state-file="commitment_state.dat" \
    --proof="proof.bin" \
    -q 10
```

Verify generated proof:
```bash
./result/bin/proof-producer \
    --stage="verify" \
    --circuit="circuit.crct" \
    --common-data="preprocessed_common_data.dat" \
    --proof="proof.bin" \
    --assignment-description-file="assignment-description.dat" \
    -q 10
```

### Using proof-producer to generate and verify an aggregated proof.
Generate circuit:
```bash
./result/bin/proof-producer \
    --stage "preset" \
    --circuit-name "zkevm" \
    --circuit="circuit.crct"
```

Generate assignemnt table from EVM trace:
```bash
./result/bin/proof-producer \
    --stage "fill-assignment" \
    --circuit-name "zkevm" \
    --trace "trace.pb" \
    --assignment-table="assignment.tbl" \
    --assignment-description-file="assignment-description.dat"
```

Partial proof, ran on each prover.
```bash
./result/bin/proof-producer \
    --stage generate-partial-proof \
    --grind-param 16 \
    --max-quotient-chunks 10 \
    --circuit           circuit.crct \
    --assignment-table  assignment.tbl \
    --common-data                  $CIRCUIT-common_data.dat \
    --preprocessed-data            $CIRCUIT-preprocessed.dat \
    --commitment-state-file        $CIRCUIT-commitment_state.dat \
    --updated-commitment-state-file $CIRCUIT-updated_commitment_state.dat \
    --assignment-description-file  assignment-description.dat \
    --challenge-file               $CIRCUIT-challenge.dat \
    --theta-power-file             $CIRCUIT-theta-power.txt \
    --proof                        $CIRCUIT-proof.dat \
    --json                         $CIRCUIT-proof.json
```

Aggregate challenges, done once on the main prover.
```bash
./result/bin/proof-producer \
    --stage="generate-aggregated-challenge" \
    --input-challenge-files challenge1.dat \
    --input-challenge-files challenge2.dat \
    --aggregated-challenge-file="aggregated_challenge.dat"
```

Compute polynomial combined_Q, done on each prover. Please notice that the caller must provide the correct value of --combined-Q-starting-power, which can be taken from "$CIRCUIT-theta-power.txt" generated on stage "partial-prove".
```bash
./result/bin/proof-producer \
    --stage="compute-combined-Q" \
    --aggregated-challenge-file="aggregated_challenge.dat" \
    --combined-Q-starting-power=0  \
    --commitment-state-file="$CIRCUIT-commitment_state.dat" \
    --combined-Q-polynomial-file="$CIRCUIT-combined-Q.dat"
```

Compute aggregated FRI proof done once on the main prover. This is a part of the complete proof. The '--assignment-description-file' can point to any description file, since only the number of rows matters.
```bash
./result/bin/proof-producer \
    --stage="aggregated-FRI" \
    --assignment-description-file="assignment-description.dat" \
    --aggregated-challenge-file="aggregated_challenge.dat" \
    --input-combined-Q-polynomial-files "$CIRCUIT1-combined-Q.dat" "$CIRCUIT2_combined-Q.dat" \
    --proof="aggregated_FRI_proof.bin" \
    --proof-of-work-file="POW.dat" \
    --consistency-checks-challenges-file="challenges.dat"
```

Compute LPC consistency check proofs for polynomial combined_Q, done on each prover.
```bash
./result/bin/proof-producer \
    --stage="consistency-checks" \
    --commitment-state-file="$CIRCUIT-commitment_scheme_state.dat" \
    --consistency-checks-challenges-file="challenges.dat" \
    --proof="$CIRCUIT-LPC_consistency_check_proof.bin"
```

Merge proofs into one final proof:
```bash

bin/proof-producer/proof-producer \
    --stage merge-proofs  \
    --partial-proof $CIRCUIT1-proof.dat \
    --partial-proof $CIRCUIT2-proof.dat \
    --initial-proof $CIRCUIT1-LPC_consistency_check_proof.bin \
    --initial-proof $CIRCUIT2-LPC_consistency_check_proof.bin \
    --proof-of-work POW.dat \
    --aggregated-FRI-proof aggregated_FRI_proof.bin \
    --proof final-proof.dat
```

Verify the final proof:
```bash

bin/proof-producer/proof-producer \
    --stage aggregated-verify  \
    --circuits $CIRCUIT1.crct $CIRCUIT2.crct\
    --assignment-description-files $CIRCUIT1-assignment-description.dat $CIRCUIT2-assignment-description2.dat \
    --common-datas $CIRCUIT1-common_data.dat $CIRCUIT2-common_data.dat \
    --agg-proof final-proof.dat
```

