//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE blueprint_plonk_circuit_builder_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
// #include <nil/blueprint/bbf/is_zero.hpp>
#include <nil/blueprint/bbf/micro_range_check.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

using namespace nil::crypto3;
using namespace nil::blueprint;

template<typename FieldType>
bool check_proof(
    const circuit<zk::snark::plonk_constraint_system<FieldType>> &bp,
    const zk::snark::plonk_assignment_table<FieldType> &assignment,
    const zk::snark::plonk_table_description<FieldType> &desc) {

    std::size_t Lambda = 9;

    typedef nil::crypto3::zk::snark::placeholder_circuit_params<FieldType> circuit_params;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_type = typename nil::crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
    using lpc_params_type = nil::crypto3::zk::commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        2 //m
    >;

    using lpc_type = nil::crypto3::zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type>;
    using lpc_scheme_type = typename nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    typename lpc_type::fri_type::params_type fri_params(1, std::ceil(log2(assignment.rows_amount())), Lambda, 2);
    lpc_scheme_type lpc_scheme(fri_params);

    std::cout << "Public preprocessor" << std::endl;
    typename nil::crypto3::zk::snark::placeholder_public_preprocessor<FieldType,
        lpc_placeholder_params_type>::preprocessed_data_type lpc_preprocessed_public_data =
            nil::crypto3::zk::snark::placeholder_public_preprocessor<FieldType, lpc_placeholder_params_type>::process(
            bp, assignment.public_table(), desc, lpc_scheme, 10);

    std::cout << "Private preprocessor" << std::endl;
    typename nil::crypto3::zk::snark::placeholder_private_preprocessor<FieldType,
       lpc_placeholder_params_type>::preprocessed_data_type lpc_preprocessed_private_data =
            nil::crypto3::zk::snark::placeholder_private_preprocessor<FieldType, lpc_placeholder_params_type>::process(
            bp, assignment.private_table(), desc);

    std::cout << "Prover" << std::endl;
    auto lpc_proof = nil::crypto3::zk::snark::placeholder_prover<FieldType, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, bp,
            lpc_scheme);

    // We must not use the same instance of lpc_scheme.
    lpc_scheme_type verifier_lpc_scheme(fri_params);

    std::cout << "Verifier" << std::endl;
    bool verifier_res = nil::crypto3::zk::snark::placeholder_verifier<FieldType, lpc_placeholder_params_type>::process(
            *lpc_preprocessed_public_data.common_data, lpc_proof, desc, bp, verifier_lpc_scheme);
    return verifier_res;
}


template <typename FieldType, template<typename, bbf::GenerationStage stage> class Component, typename... ComponentStaticInfoArgs>
void test_circuit_builder(typename Component<FieldType,bbf::GenerationStage::ASSIGNMENT>::input_type input,
                          ComponentStaticInfoArgs... args) {

    auto B = bbf::circuit_builder<FieldType,Component,ComponentStaticInfoArgs...>(args...);

    auto [at, A, desc] = B.assign(input);
    std::cout << "Input = " << A.input << std::endl;
    bool pass = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << pass << std::endl;

    if (pass) {
        bool proof = check_proof(B.get_circuit(), at, desc);
        std::cout << "Is_proved = " << proof << std::endl;
    }
}

static const std::size_t random_tests_amount = 5;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_cicruit_builder_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;
    integral_type base17 = integral_type(1) << 17;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        auto random_input = value_type(integral_type(generate_random().to_integral()) %
                                       (i % 2 ? base16 : base17));
        bbf::micro_range_check<field_type,bbf::GenerationStage::ASSIGNMENT>::input_type input = {random_input};
        test_circuit_builder<field_type,bbf::micro_range_check>(input);
    }
}

BOOST_AUTO_TEST_SUITE_END()
