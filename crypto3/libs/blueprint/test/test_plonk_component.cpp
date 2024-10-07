//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE test_plonk_component_test
// This is a test for testing different test_plonk_component modes
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
#include <nil/blueprint/components/systems/snark/plonk/flexible/constant_pow.hpp>

#include "./test_plonk_component.hpp"

#include <boost/test/unit_test.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

// We'll use consant_pow component for testing test_plonk_component
BOOST_AUTO_TEST_SUITE(test_plonk_component_test_suite)
    using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 20;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = nil::crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = nil::blueprint::components::flexible_constant_pow<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input;

BOOST_AUTO_TEST_CASE(bare) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    instance_input.x = var(0, 0, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type x = generate_random();
    typename BlueprintFieldType::integral_type pow = (BlueprintFieldType::modulus - 1)/ 4294967296;
    std::vector<value_type> public_input = {x};

    auto result_check = [&x, &pow](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            BOOST_ASSERT(var_value(assignment, real_res.y) == x.pow(pow));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, pow);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::STRONG, pow);
}

BOOST_AUTO_TEST_CASE(print_to_file) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    instance_input.x = var(0, 0, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type x = generate_random();
    typename BlueprintFieldType::integral_type pow = (BlueprintFieldType::modulus - 1)/ 4294967296;
    std::vector<value_type> public_input = {x};

    auto result_check = [&x, &pow](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            BOOST_ASSERT(var_value(assignment, real_res.y) == x.pow(pow));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, pow);
    nil::crypto3::test_component_extended<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input,
        result_check, instance_input,
        true,
        nil::blueprint::connectedness_check_type::type::STRONG,
        "./test_plonk_component0",
        false,
        pow
    );

    // This is a part just for testing read/write to file calls correctness
    //     and as an example for applications that will read circuits/assignments
    auto [bp, desc, assignments] = load_circuit_and_table_from_file<BlueprintFieldType>(
        "./test_plonk_component0_circuit.crct",
        "./test_plonk_component0_table.tbl"
    );

    BOOST_ASSERT(check_placeholder_proof<BlueprintFieldType>(bp, desc, assignments));
}

BOOST_AUTO_TEST_CASE(verify_proof) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    instance_input.x = var(0, 0, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type x = generate_random();
    typename BlueprintFieldType::integral_type pow = (BlueprintFieldType::modulus - 1)/ 4294967296;
    std::vector<value_type> public_input = {x};

    auto result_check = [&x, &pow](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            BOOST_ASSERT(var_value(assignment, real_res.y) == x.pow(pow));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, pow);
    nil::crypto3::test_component_extended<component_type, BlueprintFieldType, hash_type, Lambda>
    (
        component_instance, desc,
        public_input, result_check,
        instance_input,
        true, // expected_result
        nil::blueprint::connectedness_check_type::type::STRONG,
        "",   // output path
        true, // check real placeholder proof
        pow
    );
}

BOOST_AUTO_TEST_CASE(print_to_file_and_verify_proof) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    boost::random::uniform_int_distribution<> t_dist(0, 1);

    instance_input.x = var(0, 0, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type x = generate_random();
    typename BlueprintFieldType::integral_type pow = (BlueprintFieldType::modulus - 1)/ 4294967296;
    std::vector<value_type> public_input = {x};

    auto result_check = [&x, &pow](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            BOOST_ASSERT(var_value(assignment, real_res.y) == x.pow(pow));
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, pow);
    nil::crypto3::test_component_extended<component_type, BlueprintFieldType, hash_type, Lambda>
    (
        component_instance, desc,
        public_input, result_check,
        instance_input,
        true, // expected_result
        nil::blueprint::connectedness_check_type::type::STRONG,
        "./test_plonk_component1",   // output path
        true, // check real placeholder proof
        pow
    );

    // This is a part just for testing read/write to file calls correctness
    //     and as an example for applications that will read circuits/assignments
    auto [bp, desc, assignments] = load_circuit_and_table_from_file<BlueprintFieldType>(
        "./test_plonk_component1_circuit.crct",
        "./test_plonk_component1_table.tbl"
    );

    BOOST_ASSERT(check_placeholder_proof<BlueprintFieldType>(bp, desc, assignments));
}

BOOST_AUTO_TEST_SUITE_END()