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

#define BOOST_TEST_MODULE plonk_flexible_poseidon_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/poseidon.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, std::size_t Witnesses = 15>
void test_poseidon(std::vector<typename BlueprintFieldType::value_type> public_input,
    std::vector<typename BlueprintFieldType::value_type> expected_res){

    using FieldType = BlueprintFieldType;

    constexpr std::size_t WitnessColumns = Witnesses;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 11;

    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    using component_type =
        blueprint::components::flexible_poseidon<ArithmetizationType, FieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    constexpr std::size_t Lambda = 5;

    std::array<var, component_type::state_size> input_state_var = {var(0, 0, false, var::column_type::public_input),
     var(0, 1, false, var::column_type::public_input), var(0, 2, false, var::column_type::public_input)};
    typename component_type::input_type instance_input = {input_state_var};

    auto result_check = [&expected_res](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
        for (std::uint32_t i = 0; i < component_type::state_size; i++){
            assert(expected_res[i] == var_value(assignment, real_res.output_state[i]));
        }
    };

    std::array<std::size_t, Witnesses> witnesses;
    for( std::size_t i = 0; i < Witnesses; i++){
        witnesses[i] = i;
    }
    component_type component_instance(witnesses,std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        blueprint::connectedness_check_type::type::STRONG
    );
}

template<typename FieldType>
std::vector<typename FieldType::value_type> calculate_expected_poseidon(const typename std::vector<typename FieldType::value_type> &a) {
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

template<typename FieldType, std::size_t Witnesses = 15>
void test_poseidon_specfic_data(){
    std::vector<typename FieldType::value_type> input = {0,1,1};
    test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));

    input = {0,0,0};
    test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));

    input = {1,2,3};
    test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));

    input = {-1,-1,-1};
    test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));

    typename FieldType::value_type threeFFF = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui_modular256;
    input = {threeFFF, threeFFF, threeFFF};
    test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));
}

template<typename FieldType, std::size_t RandomDataTestsAmount, std::size_t Witnesses = 15>
void test_poseidon_random_data(){
    using generator_type = nil::crypto3::random::algebraic_engine<FieldType>;
    generator_type g;
    boost::random::mt19937 seed_seq;
    g.seed(seed_seq);
    std::vector<typename FieldType::value_type> input;

    for (std::size_t i = 0; i < RandomDataTestsAmount; i++) {
        input = {g(), g(), g()};
        test_poseidon<FieldType, Witnesses>(input, calculate_expected_poseidon<FieldType>(input));
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

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas_21) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type, 21>();
    test_poseidon_random_data<field_type, random_data_tests_amount, 21>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas_42) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type, 42>();
    test_poseidon_random_data<field_type, random_data_tests_amount, 42>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas_45) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type, 45>();
    test_poseidon_random_data<field_type, random_data_tests_amount, 45>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas_84) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type, 84>();
    test_poseidon_random_data<field_type, random_data_tests_amount, 84>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_pallas_168) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_poseidon_specfic_data<field_type, 168>();
    test_poseidon_random_data<field_type, random_data_tests_amount, 168>();
}

BOOST_AUTO_TEST_SUITE_END()
