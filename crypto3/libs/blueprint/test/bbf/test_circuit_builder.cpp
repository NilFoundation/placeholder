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
#include <nil/blueprint/bbf/is_zero.hpp>

//#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

template <typename FieldType, template<typename, bbf::GenerationStage stage> class Component, typename... ComponentStaticInfoArgs>
void test_circuit_builder(typename Component<FieldType,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input,
                          ComponentStaticInfoArgs... args) {

    auto B = bbf::circuit_builder<FieldType,Component,ComponentStaticInfoArgs...>(args...);

    auto [at, A] = B.assign(raw_input);
    std::cout << "Input = " << A.input << std::endl << "Result = " << A.res << std::endl;
    std::cout << "Is_satisfied = " << B.is_satisfied(at) << std::endl;
}

static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_cicruit_builder_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        auto random_input = value_type(integral_type(generate_random().data) % base16);
        bbf::is_zero<field_type,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input = {random_input};
        test_circuit_builder<field_type,bbf::is_zero>(raw_input);
    }
    bbf::is_zero<field_type,bbf::GenerationStage::ASSIGNMENT>::raw_input_type raw_input = {0};
    test_circuit_builder<field_type,bbf::is_zero>(raw_input);
}

BOOST_AUTO_TEST_SUITE_END()
