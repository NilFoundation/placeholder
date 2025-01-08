//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// Test circuit1 on different hashes: poseidon, keccak<256>, keccak<512>, sha2
//

#define BOOST_TEST_MODULE placeholder_hashes_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"
#include "placeholder_test_runner.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(placeholder_hashes_test)

using pallas_curve_type = algebra::curves::pallas;
using pallas_field_type = typename pallas_curve_type::base_field_type;
using pallas_poseidon_type =
    hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<pallas_field_type>>;
using alt_bn_curve_type = algebra::curves::alt_bn128<254>;
using alt_bn_field_type = typename alt_bn_curve_type::scalar_field_type;
using original_poseidon_type =
    hashes::poseidon<nil::crypto3::hashes::detail::poseidon_policy<alt_bn_field_type, 128, 2>>;
using keccak_256_type = hashes::keccak_1600<256>;
using keccak_512_type = hashes::keccak_1600<512>;
using sha2_256_type = hashes::sha2<256>;

using PallasTestRunners = boost::mpl::list<
    placeholder_test_runner<pallas_field_type, pallas_poseidon_type, pallas_poseidon_type>,
    placeholder_test_runner<pallas_field_type, keccak_256_type, keccak_256_type>,
    placeholder_test_runner<pallas_field_type, keccak_512_type, keccak_512_type>,
    placeholder_test_runner<pallas_field_type, sha2_256_type, sha2_256_type>>;

using AltBnTestRunners = boost::mpl::list<
    placeholder_test_runner<alt_bn_field_type, original_poseidon_type, original_poseidon_type>,
    placeholder_test_runner<alt_bn_field_type, keccak_256_type, keccak_256_type>,
    placeholder_test_runner<alt_bn_field_type, keccak_512_type, keccak_512_type>,
    placeholder_test_runner<alt_bn_field_type, sha2_256_type, sha2_256_type>>;

BOOST_AUTO_TEST_CASE_TEMPLATE(hash_test_pallas, TestRunner, PallasTestRunners) {
    test_tools::random_test_initializer<pallas_field_type> random_test_initializer;
    auto circuit = circuit_test_1<pallas_field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<pallas_field_type>(),
        random_test_initializer.generic_random_engine);
    TestRunner test_runner(circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE_TEMPLATE(hash_test_alt_bn, TestRunner, AltBnTestRunners) {
    test_tools::random_test_initializer<alt_bn_field_type> random_test_initializer;
    auto circuit = circuit_test_1<alt_bn_field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<alt_bn_field_type>(),
        random_test_initializer.generic_random_engine);
    TestRunner test_runner(circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_SUITE_END()
