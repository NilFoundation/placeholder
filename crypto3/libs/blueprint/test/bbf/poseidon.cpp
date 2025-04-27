//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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

#define BOOST_TEST_MODULE bbf_plonk_poseidon_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>

#include <nil/blueprint/bbf/circuit_builder.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::blueprint;

template<typename BlueprintFieldType>
void test_poseidon(std::vector<typename BlueprintFieldType::value_type> public_input,
                   std::vector<typename BlueprintFieldType::value_type> expected_res) {

    using FieldType = BlueprintFieldType;

    typename bbf::components::flexible_poseidon<FieldType,bbf::GenerationStage::ASSIGNMENT>::input_type input;
    input.state = public_input;

    auto B = bbf::circuit_builder<FieldType,bbf::components::flexible_poseidon>();
    auto [at, A, desc] = B.assign(input);
    BOOST_TEST(B.is_satisfied(at));

    for (std::uint32_t i = 0; i < public_input.size(); i++) {
        BOOST_TEST_INFO("input:    " << public_input[i].to_integral());
        BOOST_TEST_INFO("expected: " << expected_res[i].to_integral());
        BOOST_TEST_INFO("real:     " << A.res[i]);
        BOOST_TEST(A.res[i] == expected_res[i], "unexpected result for input " << i);
    }
}

template<typename FieldType, typename PolicyType>
std::vector<typename FieldType::value_type> calculate_expected_poseidon(
    const typename std::vector<typename FieldType::value_type> &a) {
    using permutation_type = nil::crypto3::hashes::detail::poseidon_permutation<PolicyType>;
    using state_type = typename permutation_type::state_type;

    state_type state;
    std::copy(a.begin(), a.end(), state.begin());
    permutation_type::permute(state);

    std::vector<typename FieldType::value_type> result(3);
    std::copy(state.begin(), state.end(), result.begin());
    return result;
}

template<typename FieldType, typename PolicyType>
void test_poseidon_specfic_data() {
    std::vector<typename FieldType::value_type> input = {0, 1, 1};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));

    input = {0, 0, 0};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));

    input = {1, 2, 3};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));

    input = {-1, -1, -1};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));

    typename FieldType::value_type threeFFF =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_big_uint256;
    input = {threeFFF, threeFFF, threeFFF};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));
}

template<typename FieldType, typename PolicyType, std::size_t RandomDataTestsAmount>
void test_poseidon_random_data() {
    using generator_type = nil::crypto3::random::algebraic_engine<FieldType>;
    generator_type g;
    boost::random::mt19937 seed_seq;
    g.seed(seed_seq);
    std::vector<typename FieldType::value_type> input;

    for (std::size_t i = 0; i < RandomDataTestsAmount; i++) {
        input = {g(), g(), g()};
        test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType, PolicyType>(input));
    }
}

constexpr static const std::size_t random_data_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_poseidon_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    using poseidon_policy = nil::crypto3::hashes::detail::pasta_poseidon_policy<field_type>;
    test_poseidon_specfic_data<field_type, poseidon_policy>();
    test_poseidon_random_data<field_type, poseidon_policy, random_data_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using poseidon_policy = nil::crypto3::hashes::detail::pasta_poseidon_policy<field_type>;
    test_poseidon_specfic_data<field_type, poseidon_policy>();
    test_poseidon_random_data<field_type, poseidon_policy, random_data_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_alt_bn128) {
    using field_type = typename crypto3::algebra::curves::alt_bn128<254>::scalar_field_type;
    using poseidon_policy = nil::crypto3::hashes::detail::poseidon_policy<field_type, 128, 2>;
    test_poseidon_specfic_data<field_type, poseidon_policy>();
    test_poseidon_random_data<field_type, poseidon_policy, random_data_tests_amount>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_bls12) {
//     using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
//     test_poseidon_specfic_data<field_type>();
//     test_poseidon_random_data<field_type, random_data_tests_amount>();
// }

BOOST_AUTO_TEST_SUITE_END()
