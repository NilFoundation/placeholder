//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE as_waksman_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/routing/as_waksman_components.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void test_as_waksman_routing_component(const std::size_t num_packets, const std::size_t packet_size) {
    blueprint<FieldType> bp;
    integer_permutation permutation(num_packets);
    permutation.random_shuffle();

    std::vector<components::blueprint_variable_vector<FieldType>> randbits(num_packets), outbits(num_packets);
    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
        randbits[packet_idx].allocate(bp, packet_size);
        outbits[packet_idx].allocate(bp, packet_size);

        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
            bp.val(randbits[packet_idx][bit_idx]) =
                (rand() % 2) ? FieldType::value_type::zero() : FieldType::value_type::zero();
        }
    }
    as_waksman_routing_component<FieldType> r(bp, num_packets, randbits, outbits);
    r.generate_gates();

    r.generate_assignments(permutation);

    BOOST_CHECK(bp.is_satisfied());
    for (std::size_t packet_idx = 0; packet_idx < num_packets; ++packet_idx) {
        for (std::size_t bit_idx = 0; bit_idx < packet_size; ++bit_idx) {
            BOOST_CHECK(bp.val(outbits[permutation.get(packet_idx)][bit_idx]) == bp.val(randbits[packet_idx][bit_idx]));
        }
    }

    bp.val(components::blueprint_variable<FieldType>(10)) = typename FieldType::value_type(12345);
    BOOST_CHECK(!bp.is_satisfied());
}

BOOST_AUTO_TEST_SUITE(as_waksman_components_test_suite)

BOOST_AUTO_TEST_CASE(as_waksman_components_test) {
}

BOOST_AUTO_TEST_SUITE_END()