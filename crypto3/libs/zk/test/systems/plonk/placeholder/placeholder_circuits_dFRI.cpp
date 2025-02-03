//---------------------------------------------------------------------------//
// Copyright (c) 2025 Martun Karapetyan <martun@nil.foundation>
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
// Test all circuits using them twice over a dFRI aggregated proof on one set of parameters (pallas and poseidon)
//

#define BOOST_TEST_MODULE placeholder_dFRI_circuits_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"
#include "placeholder_dFRI_test_runner.hpp"

BOOST_AUTO_TEST_SUITE(placeholder_dFRI_circuits)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using hash_type = hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<field_type>>;
using test_runner_type = placeholder_dFRI_test_runner<field_type, hash_type, hash_type>;

BOOST_AUTO_TEST_CASE(circuit1)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_1<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit2)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
            pi0,
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit3)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_3<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit4)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_4<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit5)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_5<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit6)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_6<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit7)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_7<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_CASE(circuit8)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_8<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}


BOOST_AUTO_TEST_CASE(circuit_fib)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_fib<field_type, 100>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()
    );
    test_runner_type test_runner(circuit, circuit);
    BOOST_CHECK(test_runner.run_test());
}

// table rows for circuit #1 -> 16
// table rows for circuit #3 -> 8
// table rows for circuit #4 -> 8
// table rows for circuit #5 -> 32
// table rows for circuit #6 -> 8
// table rows for circuit #7 -> 32
// table rows for circuit #8 -> 16

BOOST_AUTO_TEST_CASE(circuit_pairs_with_32_total_rows)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    std::vector<circuit_description<field_type, placeholder_circuit_params<field_type>>> circuits;
    circuits.push_back(circuit_test_5<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));
    circuits.push_back(circuit_test_7<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));

    for (size_t i = 0; i < circuits.size(); ++i) {
        for (size_t j = i + 1; j < circuits.size(); ++j) {
            test_runner_type test_runner(circuits[i], circuits[j]);
            BOOST_CHECK(test_runner.run_test());
        }
    }
}

BOOST_AUTO_TEST_CASE(circuit_pairs_with_16_total_rows)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    std::vector<circuit_description<field_type, placeholder_circuit_params<field_type>>> circuits;
    circuits.push_back(circuit_test_1<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));
    circuits.push_back(circuit_test_8<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));

    for (size_t i = 0; i < circuits.size(); ++i) {
        for (size_t j = i + 1; j < circuits.size(); ++j) {
            test_runner_type test_runner(circuits[i], circuits[j]);
            BOOST_CHECK(test_runner.run_test());
        }
    }
}

BOOST_AUTO_TEST_CASE(circuit_pairs_with_8_total_rows)
{
    test_tools::random_test_initializer<field_type> random_test_initializer;
    std::vector<circuit_description<field_type, placeholder_circuit_params<field_type>>> circuits;
    circuits.push_back(circuit_test_3<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));
    circuits.push_back(circuit_test_4<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));
    circuits.push_back(circuit_test_6<field_type>(
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
    ));
    for (size_t i = 0; i < circuits.size(); ++i) {
        for (size_t j = i + 1; j < circuits.size(); ++j) {
            test_runner_type test_runner(circuits[i], circuits[j]);
            BOOST_CHECK(test_runner.run_test());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
