echo "1th circuit partial proof"
./result/bin/assigner --shard-id 1 --block-hash 0x001 --path /root/tmp/out/ --target-circuits add.0 -e pallas --input 326522724692461750427768532537390503835 --input 89059515727727869117346995944635890507 --input 291547819587797372485177713898460727720 --input 194782098816759892662980765881849306481 --log-level debug
echo "2th circuit partial proof"
./result/bin/assigner --shard-id 1 --block-hash 0x001 --path /root/tmp/out/ --target-circuits add.1 -e pallas --input 326522724692461750427768532537390503835 --input 89059515727727869117346995944635890507 --input 291547819587797372485177713898460727720 --input 194782098816759892662980765881849306481 --log-level debug

echo "aggregate challenges"
./result/bin/proof-producer-multi-threaded --stage="generate-aggregated-challenge" --input-challenge-files "/root/tmp/out/challenge.0.1.0x001" "/root/tmp/out/challenge.1.1.0x001" --aggregated-challenge-file="/root/tmp/out/aggregated_challenges.1.0x001"

echo "compute Q 1th circuit"
./result/bin/proof-producer-multi-threaded --stage="compute-combined-Q" --aggregated-challenge-file="/root/tmp/out/aggregated_challenges.1.0x001" --combined-Q-starting-power=0  --commitment-state-file="/root/tmp/out/commitment_state.0.1.0x001" --combined-Q-polynomial-file="/root/tmp/out/combined_Q.0.1.0x001"
echo "compute Q 2th circuit"
./result/bin/proof-producer-multi-threaded --stage="compute-combined-Q" --aggregated-challenge-file="/root/tmp/out/aggregated_challenges.1.0x001" --combined-Q-starting-power=0  --commitment-state-file="/root/tmp/out/commitment_state.1.1.0x001" --combined-Q-polynomial-file="/root/tmp/out/combined_Q.1.1.0x001"

echo "aggregate FRY"
./result/bin/proof-producer-multi-threaded --stage="aggregated-FRI" --assignment-description-file="/root/tmp/out/assignment_table_description.0.1.0x001" --aggregated-challenge-file="/root/tmp/out/aggregated_challenges.1.0x001" --input-combined-Q-polynomial-files "/root/tmp/out/combined_Q.0.1.0x001" "/root/tmp/out/combined_Q.1.1.0x001" --proof="/root/tmp/out/aggregated_FRI_proof.1.0x001" --proof-of-work-file="/root/tmp/out/POW.1.0x001" --consistency-checks-challenges-file="/root/tmp/out/challenges.1.0x001"

echo "consistency check 1th circuit"
./result/bin/proof-producer-multi-threaded --stage="consistency-checks" --commitment-state-file="/root/tmp/out/commitment_state.0.1.0x001" --combined-Q-polynomial-file="/root/tmp/out/combined_Q.0.1.0x001" --consistency-checks-challenges-file="/root/tmp/out/challenges.1.0x001" --proof="/root/tmp/out/LPC_consistency_check_proof.0.1.0x001"
echo "consistency check 2th circuit"
./result/bin/proof-producer-multi-threaded --stage="consistency-checks" --commitment-state-file="/root/tmp/out/commitment_state.1.1.0x001" --combined-Q-polynomial-file="/root/tmp/out/combined_Q.1.1.0x001" --consistency-checks-challenges-file="/root/tmp/out/challenges.1.0x001" --proof="/root/tmp/out/LPC_consistency_check_proof.1.1.0x001"


echo "merge final proof"
./result/bin/proof-producer-multi-threaded --stage merge-proofs --partial-proof "/root/tmp/out/proof.0.1.0x001" "/root/tmp/out/proof.1.1.0x001" --initial-proof "/root/tmp/out/LPC_consistency_check_proof.0.1.0x001" "/root/tmp/out/LPC_consistency_check_proof.1.1.0x001" --aggregated-FRI-proof "/root/tmp/out/aggregated_FRI_proof.1.0x001" --proof "/root/tmp/out/final-proof.1.0x001"
