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

#define BOOST_TEST_MODULE blueprint_plonk_exp_wrapper_test

#include <boost/test/unit_test.hpp>
#include <ctime>
#include <nil/blueprint/bbf/exp_wrapper.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

using word_type = zkevm_word_type;

template<typename BlueprintFieldType>
void test_exp_wrapper(std::vector<std::array<word_type, 3>> &input_triplets, std::size_t max_rows,
                      std::size_t max_exps) {
    constexpr std::size_t WitnessColumns = 48;     // TODO
    constexpr std::size_t PublicInputColumns = 0;  // TODO
    constexpr std::size_t ConstantColumns = 0;     // TODO
    constexpr std::size_t SelectorColumns = 13;    // TODO

    // table configuration
    zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessColumns, PublicInputColumns,
                                                                ConstantColumns, SelectorColumns);

    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = assignment<ArithmetizationType>;
    using CircuitType = circuit<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = components::exp_wrapper<ArithmetizationType, BlueprintFieldType>;

    typename BlueprintFieldType::value_type expected_res = 0;

    typename component_type::input_type instance_input = {};
    instance_input.add_triplets(input_triplets);

    std::vector<typename BlueprintFieldType::value_type> public_input = {};
    std::vector<uint32_t> witnesses(WitnessColumns);
    for (uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance(witnesses, {0}, {0}, max_rows, max_exps);

    auto result_check = [&expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        // assert(expected_res == var_value(assignment, real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::NONE, max_rows, max_exps);
}

// highly inefficient 256-bit random number generator.
template<typename FieldType>
word_type random_word_type(nil::crypto3::random::algebraic_engine<FieldType> &g) {
    // TODO: there should be easier way.
    using value_type = typename FieldType::value_type;
    using integral_type = typename FieldType::integral_type;

    integral_type base128 = integral_type(1) << 128;

    integral_type hi = integral_type(g().to_integral()) % base128;
    integral_type lo = integral_type(g().to_integral()) % base128;
    word_type w_hi = hi;
    word_type w_lo = lo;
    word_type result = w_hi * base128 + w_lo;
    return result;
}

word_type exp_by_squaring(word_type a, word_type n) {
    if (n == 0x00_big_uint256) return 1;
    if (n == 0x01_big_uint256) return a;

    word_type exp = exp_by_squaring(a, n >> 1);
    word_type exp2 = exp * exp;
    if (n & 1 == 1) {
        return exp2 * a;
    }
    return exp2;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_exp_wrapper_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;

    std::size_t max_exps = 2;
    std::vector<std::array<word_type, 3>> inputs;

    word_type a1 = 0xa00e9bd49962d7b217963a3daed6f4591c2bdbd41562d5f1446dc932ac9e1975_big_uint256;
    word_type d1 = 0xacab9c07aa7d08b7652965f01307cf5a3ed09cbf08325c10af9d2029e918ac7d_big_uint256;
    word_type A1 = 0x22fcc8f007a53fb4d231a691075afd85980214380e16a5994ff90de783c28b85_big_uint256;
    word_type a2 = 0x2_big_uint256;
    word_type d2 = 0x100_big_uint256;
    word_type A2 = 0x0_big_uint256;

    inputs.push_back({a1, d1, A1});
    inputs.push_back({a2, d2, A2});

    std::size_t max_rows = 1200;
    test_exp_wrapper<field_type>(inputs, max_rows, max_exps);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exp_random_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;

    std::srand(std::time(nullptr));
    using generator_type = nil::crypto3::random::algebraic_engine<field_type>;
    generator_type g;
    boost::random::mt19937 seed_seq;
    g.seed(seed_seq);

    std::size_t max_exps = 10;
    std::vector<std::array<word_type, 3>> inputs;

    for (std::size_t i = 0; i < max_exps; i++) {
        word_type a3 = random_word_type(g);
        word_type d3 = random_word_type(g);
        word_type A3 = exp_by_squaring(a3, d3);
        // std::cout << A3 << std::endl;
        inputs.push_back({a3, d3, A3});
    }
    std::size_t max_rows = 3 * 400 * max_exps;
    test_exp_wrapper<field_type>(inputs, max_rows, max_exps);
}

BOOST_AUTO_TEST_SUITE_END()
