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
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

using namespace nil;

template<typename BlueprintFieldType>
void test_poseidon(std::vector<typename BlueprintFieldType::value_type> public_input,
                   std::vector<typename BlueprintFieldType::value_type> expected_res) {
    using FieldType = BlueprintFieldType;

    // How do I set those values
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 3;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 11;

    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
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
        typename nil::blueprint::bbf::context<BlueprintFieldType, stage::ASSIGNMENT>;
    using Flexible_Poseidon =
        typename nil::blueprint::bbf::components::flexible_poseidon<BlueprintFieldType,
                                                                    stage::ASSIGNMENT>;
    using TYPE = typename context_type::TYPE;

    AssignmentType assignment_instance(desc);
    context_type ct = context_type(assignment_instance, 18, 0);  // max_rows = 18
    std::array<TYPE, 3> input = {public_input[0].data, public_input[1].data, public_input[2].data};

    // TODO
    // ct.allocate(input[0], 0, 0, nil::blueprint::bbf::column_type::constant);
    // ct.allocate(input[1], 1, 0, nil::blueprint::bbf::column_type::constant);
    // ct.allocate(input[2], 2, 0, nil::blueprint::bbf::column_type::constant);

    Flexible_Poseidon c1 = Flexible_Poseidon(ct, input);

    // #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
    for (std::uint32_t i = 0; i < input.size(); i++) {
        std::cout << "input[" << i << "]   : " << public_input[i].data << "\n";
        std::cout << "expected[" << i << "]: " << expected_res[i].data << "\n";
        std::cout << "real[" << i << "]    : " << c1.res[i] << "\n";
        // #endif
        assert(expected_res[i] == c1.res[i]);
    }
}

template<typename FieldType>
std::vector<typename FieldType::value_type> calculate_expected_poseidon(
    const typename std::vector<typename FieldType::value_type> &a) {
    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<FieldType>;
    using permutation_type = nil::crypto3::hashes::detail::poseidon_permutation<poseidon_policy>;
    using state_type = typename permutation_type::state_type;

    state_type state;
    std::copy(a.begin(), a.end(), state.begin());
    permutation_type::permute(state);

    std::vector<typename FieldType::value_type> result(3);
    std::copy(state.begin(), state.end(), result.begin());
    return result;
}

template<typename FieldType>
void test_poseidon_specfic_data() {
    std::vector<typename FieldType::value_type> input = {0, 1, 1};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));

    input = {0, 0, 0};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));

    input = {1, 2, 3};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));

    input = {-1, -1, -1};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));

    typename FieldType::value_type threeFFF =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular256;
    input = {threeFFF, threeFFF, threeFFF};
    test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));
}

template<typename FieldType, std::size_t RandomDataTestsAmount>
void test_poseidon_random_data() {
    using generator_type = nil::crypto3::random::algebraic_engine<FieldType>;
    generator_type g;
    boost::random::mt19937 seed_seq;
    g.seed(seed_seq);
    std::vector<typename FieldType::value_type> input;

    for (std::size_t i = 0; i < RandomDataTestsAmount; i++) {
        input = {g(), g(), g()};
        test_poseidon<FieldType>(input, calculate_expected_poseidon<FieldType>(input));
    }
}

constexpr static const std::size_t random_data_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_poseidon_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    test_poseidon_specfic_data<field_type>();
    test_poseidon_random_data<field_type, random_data_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type>();
    test_poseidon_random_data<field_type, random_data_tests_amount>();
}

// BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_bls12) {
//     using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
//     test_poseidon_specfic_data<field_type>();
//     test_poseidon_random_data<field_type, random_data_tests_amount>();
// }

BOOST_AUTO_TEST_SUITE_END()
