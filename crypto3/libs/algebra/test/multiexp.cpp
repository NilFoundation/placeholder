//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE multiexp_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/container/vector.hpp>
#include <boost/mpl/list.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>

#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>


using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(multiexp_test)
/**/

template<typename curve_group_type>
class multiexp_runner {
    public:
    bool static run() {
        using point = typename curve_group_type::value_type;
        using scalar = typename curve_group_type::params_type::scalar_field_type;

        std::size_t N = 8;

        std::vector<point> points(N);
        std::vector<typename scalar::value_type> scalars(N);

        for(auto & p: points) {
            p = random_element<curve_group_type>();
        }

        for(auto & s: scalars) {
            s = random_element<scalar>();
        }

        point naive_result = policies::multiexp_method_naive_plain::process(
                points.begin(), points.end(),
                scalars.begin(), scalars.end());

        point bdlo12_result = policies::multiexp_method_BDLO12::process(
                points.begin(), points.end(),
                scalars.begin(), scalars.end());

        point bos_coster_result = policies::multiexp_method_bos_coster::process(
                points.begin(), points.end(),
                scalars.begin(), scalars.end());


        BOOST_CHECK_EQUAL(naive_result, bdlo12_result);
        BOOST_CHECK_EQUAL(naive_result, bos_coster_result);

        return (naive_result == bdlo12_result) && (naive_result == bos_coster_result);
    }
};

using multiexp_runners = boost::mpl::list<
    multiexp_runner<curves::alt_bn128_254::template g1_type<>>,
    multiexp_runner<curves::alt_bn128_254::template g2_type<>>,

    multiexp_runner<curves::bls12_377::template g1_type<>>,
    multiexp_runner<curves::bls12_377::template g2_type<>>,

    multiexp_runner<curves::bls12_381::template g1_type<>>,
    multiexp_runner<curves::bls12_381::template g2_type<>>,

    multiexp_runner<curves::mnt4_298::template g1_type<>>,
    multiexp_runner<curves::mnt4_298::template g2_type<>>,

    multiexp_runner<curves::mnt6_298::template g1_type<>>,
    multiexp_runner<curves::mnt6_298::template g2_type<>>
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(multiexp_test, runner, multiexp_runners) {
    BOOST_CHECK(runner::run());
}

BOOST_AUTO_TEST_SUITE_END()
