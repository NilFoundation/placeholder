//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

template<typename BlueprintFieldType>
void test_poseidon(std::vector<typename BlueprintFieldType::value_type> public_input,
                   std::vector<typename BlueprintFieldType::value_type> expected_res) {
    using FieldType = BlueprintFieldType;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<FieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using stage = nil::blueprint::bbf::GenerationStage;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using component_type =
        blueprint::bbf::components::flexible_poseidon<FieldType, stage::ASSIGNMENT>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    constexpr std::size_t Lambda = 5;

    using value_type = typename BlueprintFieldType::value_type;
    using context_type =
        typename nil::blueprint::bbf::generic_component<FieldType, stage::ASSIGNMENT>::context_type;

    using Flexible_Poseidon =
        typename nil::blueprint::bbf::components::flexible_poseidon<BlueprintFieldType,
                                                                    stage::ASSIGNMENT>;
    using TYPE =
        typename nil::blueprint::bbf::generic_component<FieldType, stage::ASSIGNMENT>::TYPE;

    constexpr std::size_t WitnessColumns = 10;
    auto desc = component_type::get_table_description(WitnessColumns);
    AssignmentType assignment_instance(desc);
    context_type ct = context_type(assignment_instance, desc.usable_rows_amount, 0);
    std::array<TYPE, 3> input = {public_input[0].data, public_input[1].data, public_input[2].data};

    Flexible_Poseidon c1 = Flexible_Poseidon(ct, input);

    for (std::uint32_t i = 0; i < input.size(); i++) {
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "input[" << i << "]   : " << public_input[i].data << "\n";
        std::cout << "expected[" << i << "]: " << expected_res[i].data << "\n";
        std::cout << "real[" << i << "]    : " << c1.res[i] << "\n";
#endif
        assert(expected_res[i] == c1.res[i]);
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
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular256;
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
    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
    test_poseidon_specfic_data<field_type, poseidon_policy>();
    test_poseidon_random_data<field_type, poseidon_policy, random_data_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
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
