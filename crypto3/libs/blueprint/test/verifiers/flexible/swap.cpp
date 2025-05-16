//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_verifiers_placeholder_flexible_swap_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/swap.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_flexible_swap(
    const std::array<typename BlueprintFieldType::value_type, 3> &input
){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::flexible_swap<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input;
    instance_input.inp[0] = var(0, 0, false, var::column_type::public_input);
    instance_input.inp[1] = var(0, 1, false, var::column_type::public_input);
    instance_input.inp[2] = var(0, 2, false, var::column_type::public_input);

    std::vector<value_type> public_input;
    public_input.push_back(input[0]);
    public_input.push_back(input[1]);
    public_input.push_back(input[2]);

    auto result_check = [&public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res
    ) {
        if( public_input[0] == 0){
            BOOST_CHECK(var_value(assignment, real_res.output[0]) == public_input[1]);
            BOOST_CHECK(var_value(assignment, real_res.output[1]) == public_input[2]);
        } else {
            BOOST_CHECK(var_value(assignment, real_res.output[0]) == public_input[2]);
            BOOST_CHECK(var_value(assignment, real_res.output[1]) == public_input[1]);
        }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0});
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::STRONG);
}

template <typename BlueprintFieldType, std::size_t WitnessAmount, std::size_t RandomTestsAmount>
void flexible_swap_tests() {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_flexible_swap<BlueprintFieldType, WitnessAmount>({t_dist(seed_seq), generate_random(), generate_random()});
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    flexible_swap_tests<field_type, 5, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    flexible_swap_tests<field_type, 9, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;

    flexible_swap_tests<field_type, 13, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
