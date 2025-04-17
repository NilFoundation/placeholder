//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <dtabalin@nil.foundation>
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

#define BOOST_TEST_MODULE keccak_permute_wide_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/bbf/components/hashes/keccak/keccak_permute_wide.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>

using namespace nil::blueprint::bbf;

template <typename BlueprintFieldType>
void test_permute_wide(
    std::array<typename BlueprintFieldType::value_type, 25> input
){
    using component_type = keccak_permute_wide<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
    using component_input_type = typename component_type::input_type;
    auto B = circuit_builder<BlueprintFieldType, keccak_permute_wide>();
    auto [at, A, desc] = B.assign(
        component_input_type{input}
    );
    bool is_satisfied = B.is_satisfied(at);
    std::cout << "Is_satisfied = " << is_satisfied << std::endl;
    assert(is_satisfied);
}

BOOST_AUTO_TEST_CASE(keccak_permute_wide_test) {
    using namespace nil::blueprint::bbf;
    using namespace nil::crypto3::algebra::curves;

    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::base_field_type;
    using component_type = keccak_permute_wide<field_type, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
    using value_type = typename field_type::value_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;

    std::array<value_type, 25> input;
    for (std::size_t i = 0; i < 25; i++) {
        input[i] = dis(gen);
    }
    test_permute_wide<field_type>(input);
}
