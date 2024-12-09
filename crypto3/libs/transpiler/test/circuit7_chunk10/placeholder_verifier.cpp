
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

namespace placeholder_verifier{

const size_t witness_amount = 2;
const size_t public_input_amount = 0;
const size_t constant_amount = 7;
const size_t selector_amount = 6;
const std::array<std::size_t, public_input_amount> public_input_sizes = {};
const std::size_t full_public_input_size = 0;

const bool use_lookups = true;
const size_t batches_num = 5;
const size_t commitments_num = 4;
const size_t points_num = 77;
const size_t poly_num = 39;
const size_t initial_proof_points_num = 78;
const size_t round_proof_points_num = 8;
const size_t fri_roots_num = 4;
const size_t initial_merkle_proofs_num = 50;
const size_t initial_merkle_proofs_position_num = 8;
const size_t initial_merkle_proofs_hash_num = 40;
const size_t round_merkle_proofs_position_num = 26;
const size_t round_merkle_proofs_hash_num = 26;
const size_t final_polynomial_size = 2;
const size_t lambda = 10;
const size_t rows_amount = 32;
const size_t rows_log = 5;
const size_t total_columns = 15;
const size_t sorted_columns = 9;
const size_t permutation_size = 0;
const std::array <std::size_t, public_input_amount> public_input_indices = {};
const size_t table_values_num = 32;
const size_t gates_amount = 1;
constexpr std::array<std::size_t, gates_amount> gates_selector_indices = {0};
const size_t constraints_amount = 1;
const size_t quotient_polys_start = 40;
const size_t quotient_polys_amount = 10;
const size_t lookup_sorted_polys_start = 50;
const size_t D0_size = 512;
const size_t D0_log = 9;
const pallas::base_field_type::value_type D0_omega = pallas::base_field_type::value_type(0x0x32BFB543E409054906E3866AF24325A6F8E702511EF204C674BFA596A5C9B7E5 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255);
const pallas::base_field_type::value_type omega = pallas::base_field_type::value_type(0x0x7FC67F0D2530E47F91F36DED523F7E7013069392919E4978ABC6E0F780C038C mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255);
const size_t fri_rounds = 4;
const std::array<int, gates_amount> gates_sizes = {1};
const size_t unique_points = 9;
const size_t singles_amount = 9;
const std::array<std::size_t, batches_num> batches_amount_list = {15, 2, 3, 10, 9};
pallas::base_field_type::value_type vk0 = pallas::base_field_type::value_type(0x0x21718F7FBDA33C144EB86ABF6F540BC96DC9AFDC49C0C6A14D255C1377E1ACD2 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255);
pallas::base_field_type::value_type vk1 = pallas::base_field_type::value_type(0x0x3F4216B1C0767D00C8701FEEE2847F9B73EC1D272E87B27245D3CBD72102FAAC mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255);



const size_t lookup_table_amount = 3;
const size_t lookup_gate_amount = 3;
constexpr std::array<std::size_t, lookup_table_amount> lookup_options_amount_list = {1, 2, 3};
constexpr std::array<std::size_t, lookup_table_amount> lookup_tables_columns_amount_list = {7, 2, 1};
constexpr std::size_t lookup_options_amount = 6;
constexpr std::size_t lookup_table_columns_amount = 14;

constexpr std::array<std::size_t, lookup_gate_amount> lookup_constraints_amount_list = {1, 1, 1};
constexpr std::size_t lookup_constraints_amount = 3;
constexpr std::array<std::size_t, lookup_constraints_amount> lookup_expressions_amount_list = {7, 2, 1};
constexpr std::size_t lookup_expressions_amount = 10;


constexpr std::size_t m_parameter = lookup_options_amount + lookup_constraints_amount;
constexpr std::size_t input_size_alphas = m_parameter - 1;

constexpr std::size_t input_size_lookup_gate_selectors = lookup_gate_amount;
constexpr std::size_t input_size_lookup_gate_constraints_table_ids = lookup_constraints_amount;
constexpr std::size_t input_size_lookup_gate_constraints_lookup_inputs = lookup_expressions_amount;

constexpr std::size_t input_size_lookup_table_selectors = lookup_table_amount;
constexpr std::size_t input_size_lookup_table_lookup_options = lookup_table_columns_amount;

constexpr std::size_t input_size_shifted_lookup_table_selectors = lookup_table_amount;
constexpr std::size_t input_size_shifted_lookup_table_lookup_options = lookup_table_columns_amount;

constexpr std::size_t input_size_sorted = m_parameter * 3 - 1;
	constexpr std::array<std::size_t, 39> lpc_poly_ids0 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38};
	constexpr std::array<std::size_t, 22> lpc_poly_ids1 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 17, 30, 31, 32, 33, 34, 35, 36, 37, 38};
	constexpr std::array<std::size_t, 1> lpc_poly_ids2 = {15};
	constexpr std::array<std::size_t, 1> lpc_poly_ids3 = {15};
	constexpr std::array<std::size_t, 1> lpc_poly_ids4 = {15};
	constexpr std::array<std::size_t, 2> lpc_poly_ids5 = {15, 16};
	constexpr std::array<std::size_t, 1> lpc_poly_ids6 = {15};
	constexpr std::array<std::size_t, 1> lpc_poly_ids7 = {15};
	constexpr std::array<std::size_t, 9> lpc_poly_ids8 = {30, 31, 32, 33, 34, 35, 36, 37, 38};

        

struct placeholder_proof_type{
    std::array<pallas::base_field_type::value_type, commitments_num> commitments;
    pallas::base_field_type::value_type challenge;
    std::array<pallas::base_field_type::value_type, points_num> z;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_roots;
    std::array<std::array<pallas::base_field_type::value_type, initial_proof_points_num>, lambda> initial_proof_values;
    std::array<std::array<pallas::base_field_type::value_type, round_proof_points_num>, lambda> round_proof_values;                                // lambda times
    std::array<std::array<int, initial_merkle_proofs_position_num>, lambda> initial_proof_positions;
    std::array<std::array<pallas::base_field_type::value_type, initial_merkle_proofs_hash_num>, lambda> initial_proof_hashes;
    std::array<std::array<int, round_merkle_proofs_position_num>, lambda> round_merkle_proof_positions;                                            // lambda times
    std::array<std::array<pallas::base_field_type::value_type, round_merkle_proofs_hash_num>, lambda> round_proof_hashes;                          // lambda times
    std::array<pallas::base_field_type::value_type, final_polynomial_size> final_polynomial;
};

struct placeholder_challenges_type {
    pallas::base_field_type::value_type eta;

    pallas::base_field_type::value_type perm_beta;
    pallas::base_field_type::value_type perm_gamma;
    std::array<pallas::base_field_type::value_type, 0> perm_chunk_alphas;

    pallas::base_field_type::value_type lookup_theta;
    pallas::base_field_type::value_type lookup_gamma;
    pallas::base_field_type::value_type lookup_beta;
    std::array<pallas::base_field_type::value_type, 2> lookup_chunk_alphas;

    std::array<pallas::base_field_type::value_type, 8> lookup_alphas;
    pallas::base_field_type::value_type gate_theta;
    std::array<pallas::base_field_type::value_type, 8> alphas;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_alphas;
    std::array<pallas::base_field_type::value_type, lambda> fri_x_indices;
    pallas::base_field_type::value_type lpc_theta;
    pallas::base_field_type::value_type xi;
};

typedef __attribute__((ext_vector_type(2))) typename pallas::base_field_type::value_type permutation_argument_thetas_type;
typedef __attribute__((ext_vector_type(3))) typename pallas::base_field_type::value_type permutation_argument_output_type;

struct placeholder_permutation_argument_input_type{
    std::array<typename pallas::base_field_type::value_type, permutation_size> xi_values;
    std::array<typename pallas::base_field_type::value_type, permutation_size> id_perm;
    std::array<typename pallas::base_field_type::value_type, permutation_size> sigma_perm;
    permutation_argument_thetas_type thetas;
};

struct transcript_state_type{
    std::array <pallas::base_field_type::value_type, 3> state;
    std::size_t cur;
};

void transcript(transcript_state_type &tr_state, pallas::base_field_type::value_type value) {
    if(tr_state.cur == 3){
        tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0],tr_state.state[1],tr_state.state[2]})[2];
        tr_state.state[1] = pallas::base_field_type::value_type(0);
        tr_state.state[2] = pallas::base_field_type::value_type(0);
        tr_state.cur = 1;
    }
	tr_state.state[tr_state.cur] = value;
	tr_state.cur++;
}

pallas::base_field_type::value_type transcript_challenge(transcript_state_type &tr_state) {
    tr_state.state[0] = __builtin_assigner_poseidon_pallas_base({tr_state.state[0], tr_state.state[1], tr_state.state[2]})[2];
    tr_state.state[1] = pallas::base_field_type::value_type(0);
    tr_state.state[2] = pallas::base_field_type::value_type(0);
    tr_state.cur = 1;
    return tr_state.state[0];
}

pallas::base_field_type::value_type pow_rows_amount(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 0; i < rows_log; i++){
        result = result * result;
    }
    return result;
}

pallas::base_field_type::value_type pow2(pallas::base_field_type::value_type x){
    return x*x;
}

pallas::base_field_type::value_type pow3(pallas::base_field_type::value_type x){
    return x*x*x;
}

pallas::base_field_type::value_type pow4(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result;
}

pallas::base_field_type::value_type pow5(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result * x;
}

pallas::base_field_type::value_type pow6(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x * x;
    result = result * result;
    return result;
}

pallas::base_field_type::value_type pow7(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x * x;
    result = result * result;
    return result * x;
}

pallas::base_field_type::value_type pow8(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x * x;
    result = result * result;
    return result * result;
}

pallas::base_field_type::value_type pow9(pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result = x;
    result = result * result;
    result = result * result;
    result = result * result;
    result = result * x;
    return result;
}

template<std::size_t p>
pallas::base_field_type::value_type pow(pallas::base_field_type::value_type x){
    if constexpr( p == 0 ) return pallas::base_field_type::value_type(1);
    if constexpr( p == 1 ) return x;
    pallas::base_field_type::value_type result = pow<p/2>(x);
    result = result * result;
    if constexpr( p%2 == 1 ) result = result * x;
    return result;
}

std::array<pallas::base_field_type::value_type, singles_amount> fill_singles(
    pallas::base_field_type::value_type xi,
    pallas::base_field_type::value_type eta
){
    std::array<pallas::base_field_type::value_type, singles_amount> singles;
	singles[0] = xi;
	singles[1] = xi*omega;
	singles[8] = xi*pow< 14>(omega);
	singles[6] = xi*pow< 2>(omega);
	singles[7] = xi*pow< 3>(omega);
	singles[5] = xi/omega;
	singles[4] = xi/pow< 2>(omega);
	singles[3] = xi/pow< 3>(omega);
	singles[2] = xi/pow< 7>(omega);
;
    return singles;
}

placeholder_challenges_type generate_challenges(
    const placeholder_proof_type &proof
){
    placeholder_challenges_type challenges;
    pallas::base_field_type::value_type state;
	challenges.eta = state = __builtin_assigner_poseidon_pallas_base({0, vk0, vk1})[2];
	// generate permutation argument challenges
	challenges.lookup_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[0], 0})[2];
	challenges.lookup_beta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];	challenges.lookup_gamma = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	for( std::size_t i = 0; i < 2; i++){
		challenges.lookup_chunk_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	}
	for( std::size_t i = 0; i < 8; i++){
		challenges.lookup_alphas[i] = state =__builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	}
	challenges.gate_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], 0})[2];
	challenges.alphas[0] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[1] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[2] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[3] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[4] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[5] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[6] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.alphas[7] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	challenges.xi = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[2], 0})[2];
	state = __builtin_assigner_poseidon_pallas_base({state, vk1, proof.commitments[0]})[2];
	state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], proof.commitments[2]})[2];
	challenges.lpc_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];
	for(std::size_t i = 0; i < fri_roots_num; i++){
		challenges.fri_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, proof.fri_roots[i], 0})[2];
	}
	for(std::size_t i = 0; i < lambda; i++){
		challenges.fri_x_indices[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];
	}

    return challenges;
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type> xi_polys(
    pallas::base_field_type::value_type xi
){
    pallas::base_field_type::value_type xi_n = pow_rows_amount(xi) - pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type l0 = (xi - pallas::base_field_type::value_type(1))*pallas::base_field_type::value_type(rows_amount);
    l0 = xi_n / l0;
    return std::make_pair(l0, xi_n);
}

std::array<pallas::base_field_type::value_type, constraints_amount> calculate_constraints(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
	constraints[0] = (z[30] - z[26]);


    return constraints;
}


std::array<pallas::base_field_type::value_type, lookup_expressions_amount> calculate_lookup_expressions(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, lookup_expressions_amount> expressions;
	expressions[0] = z[27];
	expressions[1] = z[28];
	expressions[2] = z[29];
	expressions[3] = z[30];
	expressions[4] = z[31];
	expressions[5] = z[32];
	expressions[6] = z[33];
	expressions[7] = z[30];
	expressions[8] = z[35];
	expressions[9] = z[34] * z[35];


    return expressions;
}
        

template<std::size_t start_index, std::size_t leaf_size>
pallas::base_field_type::value_type calculate_leaf_hash(
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> val
){
    pallas::base_field_type::value_type hash_state = pallas::base_field_type::value_type(0);
    for(std::size_t pos = 0; pos < leaf_size*2; pos+=2){
        hash_state = __builtin_assigner_poseidon_pallas_base(
            {hash_state, val[start_index + pos], val[start_index + pos+1]}
        )[2];
    }
    return hash_state;
}

struct precomputed_values_type{
    pallas::base_field_type::value_type l0;
    pallas::base_field_type::value_type Z_at_xi;
    pallas::base_field_type::value_type F_consolidated;
    pallas::base_field_type::value_type T_consolidated;
    pallas::base_field_type::value_type mask;
    pallas::base_field_type::value_type shifted_mask;
};

constexpr std::size_t L0_IND = 0;
constexpr std::size_t Z_AT_XI_IND = 1;
constexpr std::size_t F_CONSOLIDATED_IND = 2;
constexpr std::size_t T_CONSOLIDATED_IND = 3;

typedef __attribute__((ext_vector_type(2)))
                typename pallas::base_field_type::value_type pair_type;

typedef __attribute__((ext_vector_type(4)))
                typename pallas::base_field_type::value_type lookup_output_type;

typedef __attribute__((ext_vector_type(2)))
                typename pallas::base_field_type::value_type pair_type;


[[circuit]] bool placeholder_verifier(
    
    placeholder_proof_type proof
) {
   placeholder_challenges_type challenges = generate_challenges(proof);
   __builtin_assigner_exit_check_eq_pallas(challenges.xi, proof.challenge);

    precomputed_values_type precomputed_values;
    std::tie(precomputed_values.l0, precomputed_values.Z_at_xi) = xi_polys(challenges.xi);
    precomputed_values.mask = (pallas::base_field_type::value_type(1) - proof.z[2*permutation_size] - proof.z[2*permutation_size + 2]);

    // For loop in for loop removed


    std::array<pallas::base_field_type::value_type, 8> F;
    F[0] = pallas::base_field_type::value_type(0);
    F[1] = pallas::base_field_type::value_type(0);
    F[2] = pallas::base_field_type::value_type(0);
    F[3] = pallas::base_field_type::value_type(0);
    F[4] = pallas::base_field_type::value_type(0);
    F[5] = pallas::base_field_type::value_type(0);
    F[6] = pallas::base_field_type::value_type(0);
    F[7] = pallas::base_field_type::value_type(0);



    {
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_selectors> lookup_gate_selectors;
		lookup_gate_selectors[0] = proof.z[19];
		lookup_gate_selectors[1] = proof.z[20];
		lookup_gate_selectors[2] = proof.z[21];

        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_constraints_table_ids> lookup_gate_constraints_table_ids = {1, 2, 3};
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_gate_constraints_lookup_inputs> lookup_gate_constraints_lookup_inputs = calculate_lookup_expressions(proof.z);
        std::array<typename pallas::base_field_type::value_type, input_size_lookup_table_selectors> lookup_table_selectors;
		lookup_table_selectors[0] = proof.z[24];
		lookup_table_selectors[1] = proof.z[22];
		lookup_table_selectors[2] = proof.z[22];

        std::array<typename pallas::base_field_type::value_type, input_size_shifted_lookup_table_selectors> shifted_lookup_table_selectors;
		shifted_lookup_table_selectors[0] = proof.z[25];
		shifted_lookup_table_selectors[1] = proof.z[23];
		shifted_lookup_table_selectors[2] = proof.z[23];

        std::array<typename pallas::base_field_type::value_type, input_size_lookup_table_lookup_options> lookup_table_lookup_options;
		lookup_table_lookup_options[0] = proof.z[4];
		lookup_table_lookup_options[1] = proof.z[6];
		lookup_table_lookup_options[2] = proof.z[8];
		lookup_table_lookup_options[3] = proof.z[10];
		lookup_table_lookup_options[4] = proof.z[12];
		lookup_table_lookup_options[5] = proof.z[14];
		lookup_table_lookup_options[6] = proof.z[16];
		lookup_table_lookup_options[7] = proof.z[4];
		lookup_table_lookup_options[8] = proof.z[6];
		lookup_table_lookup_options[9] = proof.z[8];
		lookup_table_lookup_options[10] = proof.z[10];
		lookup_table_lookup_options[11] = proof.z[12];
		lookup_table_lookup_options[12] = proof.z[14];
		lookup_table_lookup_options[13] = proof.z[16];

        std::array<typename pallas::base_field_type::value_type, input_size_shifted_lookup_table_lookup_options> shifted_lookup_table_lookup_options;
		shifted_lookup_table_lookup_options[0] = proof.z[5];
		shifted_lookup_table_lookup_options[1] = proof.z[7];
		shifted_lookup_table_lookup_options[2] = proof.z[9];
		shifted_lookup_table_lookup_options[3] = proof.z[11];
		shifted_lookup_table_lookup_options[4] = proof.z[13];
		shifted_lookup_table_lookup_options[5] = proof.z[15];
		shifted_lookup_table_lookup_options[6] = proof.z[17];
		shifted_lookup_table_lookup_options[7] = proof.z[5];
		shifted_lookup_table_lookup_options[8] = proof.z[7];
		shifted_lookup_table_lookup_options[9] = proof.z[9];
		shifted_lookup_table_lookup_options[10] = proof.z[11];
		shifted_lookup_table_lookup_options[11] = proof.z[13];
		shifted_lookup_table_lookup_options[12] = proof.z[15];
		shifted_lookup_table_lookup_options[13] = proof.z[17];


        std::array<typename pallas::base_field_type::value_type, input_size_sorted> sorted;
        for(std::size_t i = 0; i < input_size_sorted; i++){
            sorted[i] = proof.z[lookup_sorted_polys_start + i];
        }

        typename pallas::base_field_type::value_type theta = challenges.lookup_theta;
        typename pallas::base_field_type::value_type beta = challenges.lookup_beta;
        typename pallas::base_field_type::value_type gamma = challenges.lookup_gamma;
        typename pallas::base_field_type::value_type L0 = precomputed_values.l0;
        precomputed_values.shifted_mask = pallas::base_field_type::value_type(1) - proof.z[2*permutation_size+1] - proof.z[2*permutation_size + 3];

        lookup_output_type lookup_argument;

        std::array<pallas::base_field_type::value_type, lookup_constraints_amount> lookup_input;
        pallas::base_field_type::value_type theta_acc;
		lookup_input[0] = lookup_gate_constraints_table_ids[0];
		theta_acc = theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[0] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[1] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[2] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[3] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[4] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[5] * theta_acc; theta_acc *= theta;
		lookup_input[0] += lookup_gate_constraints_lookup_inputs[6] * theta_acc; theta_acc *= theta;
		lookup_input[0] *= lookup_gate_selectors[0];
		lookup_input[1] = lookup_gate_constraints_table_ids[1];
		theta_acc = theta;
		lookup_input[1] += lookup_gate_constraints_lookup_inputs[7] * theta_acc; theta_acc *= theta;
		lookup_input[1] += lookup_gate_constraints_lookup_inputs[8] * theta_acc; theta_acc *= theta;
		lookup_input[1] *= lookup_gate_selectors[1];
		lookup_input[2] = lookup_gate_constraints_table_ids[2];
		theta_acc = theta;
		lookup_input[2] += lookup_gate_constraints_lookup_inputs[9] * theta_acc; theta_acc *= theta;
		lookup_input[2] *= lookup_gate_selectors[2];

        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_value;
        std::array<pallas::base_field_type::value_type, lookup_options_amount> lookup_shifted_value;
        pallas::base_field_type::value_type tab_id = 1;
		theta_acc = theta;
		lookup_value[0] = lookup_table_selectors[0] * pallas::base_field_type::value_type(1);
		lookup_shifted_value[0] = shifted_lookup_table_selectors[0] * pallas::base_field_type::value_type(1);
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[0] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[0] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[1] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[1] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[2] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[2] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[3] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[3] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[4] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[4] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[5] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[5] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] += lookup_table_selectors[0] * lookup_table_lookup_options[6] * theta_acc;
		lookup_shifted_value[0] += shifted_lookup_table_selectors[0] * shifted_lookup_table_lookup_options[6] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[0] *= precomputed_values.mask;
		lookup_shifted_value[0] *= precomputed_values.shifted_mask;
		theta_acc = theta;
		lookup_value[1] = lookup_table_selectors[1] * pallas::base_field_type::value_type(2);
		lookup_shifted_value[1] = shifted_lookup_table_selectors[1] * pallas::base_field_type::value_type(2);
		lookup_value[1] += lookup_table_selectors[1] * lookup_table_lookup_options[7] * theta_acc;
		lookup_shifted_value[1] += shifted_lookup_table_selectors[1] * shifted_lookup_table_lookup_options[7] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[1] += lookup_table_selectors[1] * lookup_table_lookup_options[8] * theta_acc;
		lookup_shifted_value[1] += shifted_lookup_table_selectors[1] * shifted_lookup_table_lookup_options[8] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[1] *= precomputed_values.mask;
		lookup_shifted_value[1] *= precomputed_values.shifted_mask;
		theta_acc = theta;
		lookup_value[2] = lookup_table_selectors[1] * pallas::base_field_type::value_type(2);
		lookup_shifted_value[2] = shifted_lookup_table_selectors[1] * pallas::base_field_type::value_type(2);
		lookup_value[2] += lookup_table_selectors[1] * lookup_table_lookup_options[9] * theta_acc;
		lookup_shifted_value[2] += shifted_lookup_table_selectors[1] * shifted_lookup_table_lookup_options[9] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[2] += lookup_table_selectors[1] * lookup_table_lookup_options[10] * theta_acc;
		lookup_shifted_value[2] += shifted_lookup_table_selectors[1] * shifted_lookup_table_lookup_options[10] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[2] *= precomputed_values.mask;
		lookup_shifted_value[2] *= precomputed_values.shifted_mask;
		theta_acc = theta;
		lookup_value[3] = lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_shifted_value[3] = shifted_lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_value[3] += lookup_table_selectors[2] * lookup_table_lookup_options[11] * theta_acc;
		lookup_shifted_value[3] += shifted_lookup_table_selectors[2] * shifted_lookup_table_lookup_options[11] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[3] *= precomputed_values.mask;
		lookup_shifted_value[3] *= precomputed_values.shifted_mask;
		theta_acc = theta;
		lookup_value[4] = lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_shifted_value[4] = shifted_lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_value[4] += lookup_table_selectors[2] * lookup_table_lookup_options[12] * theta_acc;
		lookup_shifted_value[4] += shifted_lookup_table_selectors[2] * shifted_lookup_table_lookup_options[12] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[4] *= precomputed_values.mask;
		lookup_shifted_value[4] *= precomputed_values.shifted_mask;
		theta_acc = theta;
		lookup_value[5] = lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_shifted_value[5] = shifted_lookup_table_selectors[2] * pallas::base_field_type::value_type(3);
		lookup_value[5] += lookup_table_selectors[2] * lookup_table_lookup_options[13] * theta_acc;
		lookup_shifted_value[5] += shifted_lookup_table_selectors[2] * shifted_lookup_table_lookup_options[13] * theta_acc;
		theta_acc = theta_acc * theta;
		lookup_value[5] *= precomputed_values.mask;
		lookup_shifted_value[5] *= precomputed_values.shifted_mask;


        pallas::base_field_type::value_type g = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type h = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type previous_value = proof.z[36];
        pallas::base_field_type::value_type current_value;
        lookup_argument[2] = pallas::base_field_type::value_type(0);

		g = g *(pallas::base_field_type::value_type(1)+beta)*(gamma + lookup_input[0]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[0] + beta * sorted[1]);
		g = g *(pallas::base_field_type::value_type(1)+beta)*(gamma + lookup_input[1]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[3] + beta * sorted[4]);
		g = g *(pallas::base_field_type::value_type(1)+beta)*(gamma + lookup_input[2]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[6] + beta * sorted[7]);
		current_value = proof.z[38];
		lookup_argument[2] += challenges.lookup_chunk_alphas[0] * (previous_value * g - current_value * h);
		previous_value = current_value;
		g = pallas::base_field_type::value_type(1); h = pallas::base_field_type::value_type(1);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[0] + beta * lookup_shifted_value[0]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[9] + beta * sorted[10]);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[1] + beta * lookup_shifted_value[1]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[12] + beta * sorted[13]);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[2] + beta * lookup_shifted_value[2]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[15] + beta * sorted[16]);
		current_value = proof.z[39];
		lookup_argument[2] += challenges.lookup_chunk_alphas[1] * (previous_value * g - current_value * h);
		previous_value = current_value;
		g = pallas::base_field_type::value_type(1); h = pallas::base_field_type::value_type(1);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[3] + beta * lookup_shifted_value[3]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[18] + beta * sorted[19]);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[4] + beta * lookup_shifted_value[4]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[21] + beta * sorted[22]);
		g = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value[5] + beta * lookup_shifted_value[5]);
		h = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted[24] + beta * sorted[25]);

        lookup_argument[0] = (pallas::base_field_type::value_type(1) - proof.z[36]) * L0;
        lookup_argument[1] = proof.z[2*permutation_size]*(proof.z[36] * proof.z[36] - proof.z[36]);
        lookup_argument[2] += (previous_value * g - proof.z[36 + 1] * h);
        lookup_argument[2] *= -precomputed_values.mask;
        lookup_argument[3] = pallas::base_field_type::value_type(0);
        for(std::size_t i = 0; i < input_size_alphas; i++){
            lookup_argument[3] =  lookup_argument[3] + challenges.lookup_alphas[i] * (sorted[3*i + 3] - sorted[3*i + 2]);
        }
        lookup_argument[3] = lookup_argument[3] * L0;
        F[3] = lookup_argument[0];
        F[4] = lookup_argument[1];
        F[5] = lookup_argument[2];
        F[6] = lookup_argument[3];
    }
        
    if constexpr( gates_amount > 0) {
        std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
        std::array<pallas::base_field_type::value_type, gates_amount> selectors;
        constraints = calculate_constraints(proof.z);

		pallas::base_field_type::value_type theta_acc(1);
		F[7] += proof.z[18] * constraints[0] * theta_acc; theta_acc *= challenges.gate_theta;


        F[7] *= precomputed_values.mask;
    }

    precomputed_values.F_consolidated = pallas::base_field_type::value_type(0);
    for(std::size_t i = 0; i < 8; i++){
        F[i] *= challenges.alphas[i];
        precomputed_values.F_consolidated += F[i];
    }

    precomputed_values.T_consolidated = pallas::base_field_type::value_type(0);
    pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
    for(std::size_t i = 0; i < quotient_polys_amount; i++){
        precomputed_values.T_consolidated += proof.z[quotient_polys_start + i] * factor;
        factor *= (precomputed_values.Z_at_xi + pallas::base_field_type::value_type(1));
    }
    __builtin_assigner_exit_check(precomputed_values.F_consolidated == precomputed_values.T_consolidated * precomputed_values.Z_at_xi);

    // Commitment scheme
    std::array<pallas::base_field_type::value_type, singles_amount> singles = fill_singles(challenges.xi, challenges.eta);
    std::array<pallas::base_field_type::value_type, unique_points+1> U{pallas::base_field_type::value_type(0)};

	pallas::base_field_type::value_type theta_acc = pallas::base_field_type::value_type(1);

	U[0] = pallas::base_field_type::value_type(0);
	U[0] += theta_acc * proof.z[0]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[2]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[4]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[6]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[8]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[10]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[12]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[14]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[16]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[18]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[19]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[20]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[21]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[22]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[24]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[30]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[35]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[36]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[38]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[39]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[40]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[41]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[42]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[43]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[44]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[45]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[46]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[47]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[48]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[49]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[50]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[53]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[56]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[59]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[62]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[65]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[68]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[71]; theta_acc *= challenges.lpc_theta;
	U[0] += theta_acc * proof.z[74]; theta_acc *= challenges.lpc_theta;

	U[1] = pallas::base_field_type::value_type(0);
	U[1] += theta_acc * proof.z[1]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[3]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[5]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[7]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[9]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[11]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[13]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[15]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[17]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[23]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[25]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[31]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[37]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[51]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[54]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[57]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[60]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[63]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[66]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[69]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[72]; theta_acc *= challenges.lpc_theta;
	U[1] += theta_acc * proof.z[75]; theta_acc *= challenges.lpc_theta;

	U[2] = pallas::base_field_type::value_type(0);
	U[2] += theta_acc * proof.z[26]; theta_acc *= challenges.lpc_theta;

	U[3] = pallas::base_field_type::value_type(0);
	U[3] += theta_acc * proof.z[27]; theta_acc *= challenges.lpc_theta;

	U[4] = pallas::base_field_type::value_type(0);
	U[4] += theta_acc * proof.z[28]; theta_acc *= challenges.lpc_theta;

	U[5] = pallas::base_field_type::value_type(0);
	U[5] += theta_acc * proof.z[29]; theta_acc *= challenges.lpc_theta;
	U[5] += theta_acc * proof.z[34]; theta_acc *= challenges.lpc_theta;

	U[6] = pallas::base_field_type::value_type(0);
	U[6] += theta_acc * proof.z[32]; theta_acc *= challenges.lpc_theta;

	U[7] = pallas::base_field_type::value_type(0);
	U[7] += theta_acc * proof.z[33]; theta_acc *= challenges.lpc_theta;

	U[8] = pallas::base_field_type::value_type(0);
	U[8] += theta_acc * proof.z[52]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[55]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[58]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[61]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[64]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[67]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[70]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[73]; theta_acc *= challenges.lpc_theta;
	U[8] += theta_acc * proof.z[76]; theta_acc *= challenges.lpc_theta;

	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x25028413607350C95CB2737B19762FEC8F0D2AD9265327959EA408C2AEBCE349 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x711DA9E192821D6C46F5F23D854015FA604641642E61D9FDCEA52BE1C69B44F mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x1CA940421574E9431A983C5FB47C13C598A5DBA06D0507D89A3DE45C2CB88680 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x9F93CEAA7A11C28019770B515887602EFBF1A3F906FD9CBFB6EA5465D19B905 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x2E830CE253A490984769A47B5AA6882B590BF2688BD1A7B96A522C77476780F6 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0xC50ED252B73A39F54A618EB2EB73D15E4698B14731C6E186DA54763E8B8B57A mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0xC795351F23FA0172FE3803278E89FC15282DA8F234A172B5CF5316E761620E9 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x2B6479BD1EA6A45030E8F06B4FDD743BF8BBA0C7180600D724F917B9CA72CD81 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x36C5BAAE2BB45D35E8FC11DB799E8882790732BB7B255ACF2D5FB4BA751A0F72 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x77970A6368DD6ED601494331B3CED4F5A333EFF0B31A246BAD88B5F39399AC7 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x6E529C0C5E28A672846D6FD3E53DA775E988248C4E1337AF62101BB9A2AA574 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x13EBA14E86648D5FDEDE2D610E35CEB3ED350A0CA013B3E61D9ED56C34D9686A mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x22825163D113EBD6930E5A066ACAD991ABD7728A085F9676171FDB65095A2769 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x36A1AC8128872B782B2DFEF4705518B1137C269D1E44B19C704142A4081AD96A mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;
	U[unique_points] += theta_acc * pallas::base_field_type::value_type(0x0x2BE0A4E2A88CC05E67E05B11FA75C0E0BAA1E4E8F367DDF5400BC9AE013F4E00 mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255); theta_acc *= challenges.lpc_theta;



    std::array<std::array<typename pallas::base_field_type::value_type, 3>, D0_log> res;
    std::size_t round_proof_ind = 0;
    std::size_t initial_proof_ind = 0;
    std::size_t initial_proof_hash_ind = 0;
    pallas::base_field_type::value_type interpolant;
    std::size_t cur_val = 0;
    std::size_t round_proof_hash_ind = 0;

    for(std::size_t i = 0; i < lambda; i++){
        cur_val = 0;
        pallas::base_field_type::value_type x(1);
        pallas::base_field_type::value_type x_challenge = challenges.fri_x_indices[i];
        pallas::base_field_type::value_type x_2(1);
		x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x;x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x; x = x * x_challenge; x = x * x; x = x * x_challenge; x = x * x;x = x * x; x = x * x_challenge; x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;x = x * x;
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][7] + (1 - proof.initial_proof_positions[i][7]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][6] + (1 - proof.initial_proof_positions[i][6]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][5] + (1 - proof.initial_proof_positions[i][5]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][4] + (1 - proof.initial_proof_positions[i][4]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][3] + (1 - proof.initial_proof_positions[i][3]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][2] + (1 - proof.initial_proof_positions[i][2]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][1] + (1 - proof.initial_proof_positions[i][1]) * D0_omega);
		x_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i][0] + (1 - proof.initial_proof_positions[i][0]) * D0_omega);

        __builtin_assigner_exit_check(x == x_2 || x == -x_2);

        pallas::base_field_type::value_type hash_state;
        pallas::base_field_type::value_type pos;
        pallas::base_field_type::value_type npos;
		hash_state = calculate_leaf_hash<0,15>(proof.initial_proof_values[i]);
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][0], npos * hash_state + pos * proof.initial_proof_hashes[i][0]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][1], npos * hash_state + pos * proof.initial_proof_hashes[i][1]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][2], npos * hash_state + pos * proof.initial_proof_hashes[i][2]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][3], npos * hash_state + pos * proof.initial_proof_hashes[i][3]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][4], npos * hash_state + pos * proof.initial_proof_hashes[i][4]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][5], npos * hash_state + pos * proof.initial_proof_hashes[i][5]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][6], npos * hash_state + pos * proof.initial_proof_hashes[i][6]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][7], npos * hash_state + pos * proof.initial_proof_hashes[i][7]})[2];
		__builtin_assigner_exit_check(hash_state == pallas::base_field_type::value_type(0x0x3F4216B1C0767D00C8701FEEE2847F9B73EC1D272E87B27245D3CBD72102FAAC mod 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001_big_uint255));

		hash_state = calculate_leaf_hash<30,2>(proof.initial_proof_values[i]);
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][8], npos * hash_state + pos * proof.initial_proof_hashes[i][8]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][9], npos * hash_state + pos * proof.initial_proof_hashes[i][9]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][10], npos * hash_state + pos * proof.initial_proof_hashes[i][10]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][11], npos * hash_state + pos * proof.initial_proof_hashes[i][11]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][12], npos * hash_state + pos * proof.initial_proof_hashes[i][12]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][13], npos * hash_state + pos * proof.initial_proof_hashes[i][13]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][14], npos * hash_state + pos * proof.initial_proof_hashes[i][14]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][15], npos * hash_state + pos * proof.initial_proof_hashes[i][15]})[2];
		__builtin_assigner_exit_check(hash_state == proof.commitments[0]);

		hash_state = calculate_leaf_hash<34,3>(proof.initial_proof_values[i]);
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][16], npos * hash_state + pos * proof.initial_proof_hashes[i][16]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][17], npos * hash_state + pos * proof.initial_proof_hashes[i][17]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][18], npos * hash_state + pos * proof.initial_proof_hashes[i][18]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][19], npos * hash_state + pos * proof.initial_proof_hashes[i][19]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][20], npos * hash_state + pos * proof.initial_proof_hashes[i][20]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][21], npos * hash_state + pos * proof.initial_proof_hashes[i][21]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][22], npos * hash_state + pos * proof.initial_proof_hashes[i][22]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][23], npos * hash_state + pos * proof.initial_proof_hashes[i][23]})[2];
		__builtin_assigner_exit_check(hash_state == proof.commitments[1]);

		hash_state = calculate_leaf_hash<40,10>(proof.initial_proof_values[i]);
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][24], npos * hash_state + pos * proof.initial_proof_hashes[i][24]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][25], npos * hash_state + pos * proof.initial_proof_hashes[i][25]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][26], npos * hash_state + pos * proof.initial_proof_hashes[i][26]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][27], npos * hash_state + pos * proof.initial_proof_hashes[i][27]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][28], npos * hash_state + pos * proof.initial_proof_hashes[i][28]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][29], npos * hash_state + pos * proof.initial_proof_hashes[i][29]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][30], npos * hash_state + pos * proof.initial_proof_hashes[i][30]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][31], npos * hash_state + pos * proof.initial_proof_hashes[i][31]})[2];
		__builtin_assigner_exit_check(hash_state == proof.commitments[2]);

		hash_state = calculate_leaf_hash<60,9>(proof.initial_proof_values[i]);
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][32], npos * hash_state + pos * proof.initial_proof_hashes[i][32]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][33], npos * hash_state + pos * proof.initial_proof_hashes[i][33]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][34], npos * hash_state + pos * proof.initial_proof_hashes[i][34]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][35], npos * hash_state + pos * proof.initial_proof_hashes[i][35]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][36], npos * hash_state + pos * proof.initial_proof_hashes[i][36]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][37], npos * hash_state + pos * proof.initial_proof_hashes[i][37]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][38], npos * hash_state + pos * proof.initial_proof_hashes[i][38]})[2];
		pos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		hash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i][39], npos * hash_state + pos * proof.initial_proof_hashes[i][39]})[2];
		__builtin_assigner_exit_check(hash_state == proof.commitments[3]);


        pallas::base_field_type::value_type y0;
        pallas::base_field_type::value_type y1;
        y0 = pallas::base_field_type::value_type(0);
        y1 = pallas::base_field_type::value_type(0);
        theta_acc = pallas::base_field_type::value_type(1);
        pallas::base_field_type::value_type Q0;
        pallas::base_field_type::value_type Q1;

		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][0] * theta_acc;
		Q1 += proof.initial_proof_values[i][1] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][2] * theta_acc;
		Q1 += proof.initial_proof_values[i][3] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][4] * theta_acc;
		Q1 += proof.initial_proof_values[i][5] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][6] * theta_acc;
		Q1 += proof.initial_proof_values[i][7] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][8] * theta_acc;
		Q1 += proof.initial_proof_values[i][9] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][10] * theta_acc;
		Q1 += proof.initial_proof_values[i][11] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][12] * theta_acc;
		Q1 += proof.initial_proof_values[i][13] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][14] * theta_acc;
		Q1 += proof.initial_proof_values[i][15] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][16] * theta_acc;
		Q1 += proof.initial_proof_values[i][17] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][18] * theta_acc;
		Q1 += proof.initial_proof_values[i][19] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][20] * theta_acc;
		Q1 += proof.initial_proof_values[i][21] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][22] * theta_acc;
		Q1 += proof.initial_proof_values[i][23] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][24] * theta_acc;
		Q1 += proof.initial_proof_values[i][25] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][26] * theta_acc;
		Q1 += proof.initial_proof_values[i][27] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][28] * theta_acc;
		Q1 += proof.initial_proof_values[i][29] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][32] * theta_acc;
		Q1 += proof.initial_proof_values[i][33] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][34] * theta_acc;
		Q1 += proof.initial_proof_values[i][35] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][36] * theta_acc;
		Q1 += proof.initial_proof_values[i][37] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][38] * theta_acc;
		Q1 += proof.initial_proof_values[i][39] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][40] * theta_acc;
		Q1 += proof.initial_proof_values[i][41] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][42] * theta_acc;
		Q1 += proof.initial_proof_values[i][43] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][44] * theta_acc;
		Q1 += proof.initial_proof_values[i][45] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][46] * theta_acc;
		Q1 += proof.initial_proof_values[i][47] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][48] * theta_acc;
		Q1 += proof.initial_proof_values[i][49] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][50] * theta_acc;
		Q1 += proof.initial_proof_values[i][51] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][52] * theta_acc;
		Q1 += proof.initial_proof_values[i][53] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][54] * theta_acc;
		Q1 += proof.initial_proof_values[i][55] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][56] * theta_acc;
		Q1 += proof.initial_proof_values[i][57] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][58] * theta_acc;
		Q1 += proof.initial_proof_values[i][59] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][60] * theta_acc;
		Q1 += proof.initial_proof_values[i][61] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][62] * theta_acc;
		Q1 += proof.initial_proof_values[i][63] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][64] * theta_acc;
		Q1 += proof.initial_proof_values[i][65] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][66] * theta_acc;
		Q1 += proof.initial_proof_values[i][67] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][68] * theta_acc;
		Q1 += proof.initial_proof_values[i][69] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][70] * theta_acc;
		Q1 += proof.initial_proof_values[i][71] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][72] * theta_acc;
		Q1 += proof.initial_proof_values[i][73] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][74] * theta_acc;
		Q1 += proof.initial_proof_values[i][75] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][76] * theta_acc;
		Q1 += proof.initial_proof_values[i][77] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[0];
		Q1 -= U[0];
		Q0 /= (x_2 - singles[0]);
		Q1 /= (-x_2 - singles[0]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][0] * theta_acc;
		Q1 += proof.initial_proof_values[i][1] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][2] * theta_acc;
		Q1 += proof.initial_proof_values[i][3] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][4] * theta_acc;
		Q1 += proof.initial_proof_values[i][5] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][6] * theta_acc;
		Q1 += proof.initial_proof_values[i][7] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][8] * theta_acc;
		Q1 += proof.initial_proof_values[i][9] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][10] * theta_acc;
		Q1 += proof.initial_proof_values[i][11] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][12] * theta_acc;
		Q1 += proof.initial_proof_values[i][13] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][14] * theta_acc;
		Q1 += proof.initial_proof_values[i][15] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][16] * theta_acc;
		Q1 += proof.initial_proof_values[i][17] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][26] * theta_acc;
		Q1 += proof.initial_proof_values[i][27] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][28] * theta_acc;
		Q1 += proof.initial_proof_values[i][29] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][34] * theta_acc;
		Q1 += proof.initial_proof_values[i][35] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][60] * theta_acc;
		Q1 += proof.initial_proof_values[i][61] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][62] * theta_acc;
		Q1 += proof.initial_proof_values[i][63] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][64] * theta_acc;
		Q1 += proof.initial_proof_values[i][65] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][66] * theta_acc;
		Q1 += proof.initial_proof_values[i][67] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][68] * theta_acc;
		Q1 += proof.initial_proof_values[i][69] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][70] * theta_acc;
		Q1 += proof.initial_proof_values[i][71] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][72] * theta_acc;
		Q1 += proof.initial_proof_values[i][73] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][74] * theta_acc;
		Q1 += proof.initial_proof_values[i][75] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][76] * theta_acc;
		Q1 += proof.initial_proof_values[i][77] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[1];
		Q1 -= U[1];
		Q0 /= (x_2 - singles[1]);
		Q1 /= (-x_2 - singles[1]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[2];
		Q1 -= U[2];
		Q0 /= (x_2 - singles[2]);
		Q1 /= (-x_2 - singles[2]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[3];
		Q1 -= U[3];
		Q0 /= (x_2 - singles[3]);
		Q1 /= (-x_2 - singles[3]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[4];
		Q1 -= U[4];
		Q0 /= (x_2 - singles[4]);
		Q1 /= (-x_2 - singles[4]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][32] * theta_acc;
		Q1 += proof.initial_proof_values[i][33] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[5];
		Q1 -= U[5];
		Q0 /= (x_2 - singles[5]);
		Q1 /= (-x_2 - singles[5]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[6];
		Q1 -= U[6];
		Q0 /= (x_2 - singles[6]);
		Q1 /= (-x_2 - singles[6]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][30] * theta_acc;
		Q1 += proof.initial_proof_values[i][31] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[7];
		Q1 -= U[7];
		Q0 /= (x_2 - singles[7]);
		Q1 /= (-x_2 - singles[7]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][60] * theta_acc;
		Q1 += proof.initial_proof_values[i][61] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][62] * theta_acc;
		Q1 += proof.initial_proof_values[i][63] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][64] * theta_acc;
		Q1 += proof.initial_proof_values[i][65] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][66] * theta_acc;
		Q1 += proof.initial_proof_values[i][67] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][68] * theta_acc;
		Q1 += proof.initial_proof_values[i][69] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][70] * theta_acc;
		Q1 += proof.initial_proof_values[i][71] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][72] * theta_acc;
		Q1 += proof.initial_proof_values[i][73] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][74] * theta_acc;
		Q1 += proof.initial_proof_values[i][75] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][76] * theta_acc;
		Q1 += proof.initial_proof_values[i][77] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[8];
		Q1 -= U[8];
		Q0 /= (x_2 - singles[8]);
		Q1 /= (-x_2 - singles[8]);
		y0 += Q0;
		y1 += Q1;
		Q0 = pallas::base_field_type::value_type(0);
		Q1 = pallas::base_field_type::value_type(0);
		Q0 += proof.initial_proof_values[i][0] * theta_acc;
		Q1 += proof.initial_proof_values[i][1] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][2] * theta_acc;
		Q1 += proof.initial_proof_values[i][3] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][4] * theta_acc;
		Q1 += proof.initial_proof_values[i][5] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][6] * theta_acc;
		Q1 += proof.initial_proof_values[i][7] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][8] * theta_acc;
		Q1 += proof.initial_proof_values[i][9] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][10] * theta_acc;
		Q1 += proof.initial_proof_values[i][11] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][12] * theta_acc;
		Q1 += proof.initial_proof_values[i][13] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][14] * theta_acc;
		Q1 += proof.initial_proof_values[i][15] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][16] * theta_acc;
		Q1 += proof.initial_proof_values[i][17] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][18] * theta_acc;
		Q1 += proof.initial_proof_values[i][19] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][20] * theta_acc;
		Q1 += proof.initial_proof_values[i][21] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][22] * theta_acc;
		Q1 += proof.initial_proof_values[i][23] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][24] * theta_acc;
		Q1 += proof.initial_proof_values[i][25] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][26] * theta_acc;
		Q1 += proof.initial_proof_values[i][27] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 += proof.initial_proof_values[i][28] * theta_acc;
		Q1 += proof.initial_proof_values[i][29] * theta_acc;
		theta_acc *= challenges.lpc_theta;
		Q0 -= U[unique_points];
		Q1 -= U[unique_points];
		Q0 /= (x_2 - challenges.eta);
		Q1 /= (-x_2 - challenges.eta);
		y0 += Q0;
		y1 += Q1;


        std::size_t D = D0_log - 1;
        pallas::base_field_type::value_type rhash;

		pos = res[0][2]; npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, y0, y1})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][0]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][0], npos * rhash + pos * proof.round_proof_hashes[i][0]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][1]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][1], npos * rhash + pos * proof.round_proof_hashes[i][1]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][2]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][2], npos * rhash + pos * proof.round_proof_hashes[i][2]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][3]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][3], npos * rhash + pos * proof.round_proof_hashes[i][3]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][4]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][4], npos * rhash + pos * proof.round_proof_hashes[i][4]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][5]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][5], npos * rhash + pos * proof.round_proof_hashes[i][5]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][6]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][6], npos * rhash + pos * proof.round_proof_hashes[i][6]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][7]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][7], npos * rhash + pos * proof.round_proof_hashes[i][7]})[2];
		__builtin_assigner_exit_check(rhash == proof.fri_roots[0]);

		pos = res[1][2]; npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, proof.round_proof_values[i][0], proof.round_proof_values[i][1]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][8]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][8], npos * rhash + pos * proof.round_proof_hashes[i][8]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][9]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][9], npos * rhash + pos * proof.round_proof_hashes[i][9]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][10]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][10], npos * rhash + pos * proof.round_proof_hashes[i][10]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][11]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][11], npos * rhash + pos * proof.round_proof_hashes[i][11]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][12]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][12], npos * rhash + pos * proof.round_proof_hashes[i][12]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][13]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][13], npos * rhash + pos * proof.round_proof_hashes[i][13]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][14]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][14], npos * rhash + pos * proof.round_proof_hashes[i][14]})[2];
		__builtin_assigner_exit_check(rhash == proof.fri_roots[1]);

		pos = res[2][2]; npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, proof.round_proof_values[i][2], proof.round_proof_values[i][3]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][15]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][15], npos * rhash + pos * proof.round_proof_hashes[i][15]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][16]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][16], npos * rhash + pos * proof.round_proof_hashes[i][16]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][17]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][17], npos * rhash + pos * proof.round_proof_hashes[i][17]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][18]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][18], npos * rhash + pos * proof.round_proof_hashes[i][18]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][19]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][19], npos * rhash + pos * proof.round_proof_hashes[i][19]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][20]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][20], npos * rhash + pos * proof.round_proof_hashes[i][20]})[2];
		__builtin_assigner_exit_check(rhash == proof.fri_roots[2]);

		pos = res[3][2]; npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, proof.round_proof_values[i][4], proof.round_proof_values[i][5]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][21]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][21], npos * rhash + pos * proof.round_proof_hashes[i][21]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][22]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][22], npos * rhash + pos * proof.round_proof_hashes[i][22]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][23]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][23], npos * rhash + pos * proof.round_proof_hashes[i][23]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][24]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][24], npos * rhash + pos * proof.round_proof_hashes[i][24]})[2];
		pos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][25]); npos = pallas::base_field_type::value_type(1) - pos;
		rhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i][25], npos * rhash + pos * proof.round_proof_hashes[i][25]})[2];
		__builtin_assigner_exit_check(rhash == proof.fri_roots[3]);

		interpolant = __builtin_assigner_fri_lin_inter(x_2, y0, y1, challenges.fri_alphas[0]);
		__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][7] * (interpolant - proof.round_proof_values[i][0]),0);
		__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][7]) * (interpolant - proof.round_proof_values[i][1]),0);
		
		y0 = proof.round_proof_values[i][0];
		y1 = proof.round_proof_values[i][1];
		x = x * x;
		interpolant = __builtin_assigner_fri_lin_inter(2 * proof.initial_proof_positions[i][7] * x - x, y0, y1, challenges.fri_alphas[1]);
		__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][6] * (interpolant - proof.round_proof_values[i][2]),0);
		__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][6]) * (interpolant - proof.round_proof_values[i][3]),0);
		
		y0 = proof.round_proof_values[i][2];
		y1 = proof.round_proof_values[i][3];
		x = x * x;
		interpolant = __builtin_assigner_fri_lin_inter(2 * proof.initial_proof_positions[i][6] * x - x, y0, y1, challenges.fri_alphas[2]);
		__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][5] * (interpolant - proof.round_proof_values[i][4]),0);
		__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][5]) * (interpolant - proof.round_proof_values[i][5]),0);
		
		y0 = proof.round_proof_values[i][4];
		y1 = proof.round_proof_values[i][5];
		x = x * x;
		interpolant = __builtin_assigner_fri_lin_inter(2 * proof.initial_proof_positions[i][5] * x - x, y0, y1, challenges.fri_alphas[3]);
		__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][4] * (interpolant - proof.round_proof_values[i][6]),0);
		__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][4]) * (interpolant - proof.round_proof_values[i][7]),0);
		
		y0 = proof.round_proof_values[i][6];
		y1 = proof.round_proof_values[i][7];
		x = x * x;
		x = 2 * proof.initial_proof_positions[i][4] * x - x;


        interpolant = pallas::base_field_type::value_type(0);
        pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y0);

        x = -x;
        interpolant = pallas::base_field_type::value_type(0);
        factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y1);
	}
    return true;
}

}
    