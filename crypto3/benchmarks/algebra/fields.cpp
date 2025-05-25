//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_fields_bench_test

#include <cstddef>
#include <format>
#include <iostream>
#include <string>
#include <tuple>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <boost/core/demangle.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>
#include <nil/crypto3/algebra/fields/goldilocks.hpp>
#include <nil/crypto3/algebra/fields/koalabear.hpp>
#include <nil/crypto3/algebra/fields/mersenne31.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

#include <nil/crypto3/bench/benchmark.hpp>

using namespace nil::crypto3::algebra;

template<typename Field>
std::string field_name() {
    auto demangled = boost::core::demangle(typeid(Field).name());
    std::size_t last_colon = demangled.find_last_of(':');
    if (last_colon != std::string::npos) {
        demangled = demangled.substr(last_colon + 1);
    }
    return demangled;
}

template<class Field>
void run_perf_test(std::string const& field_name) {
    using V = typename Field::value_type;

    std::cout << std::endl;

    auto bench_name = [&](std::string const& op) {
        return std::format("{:29} {:7}:", field_name, op);
    };

    constexpr std::size_t INDEPENDENT_FOLDS = 10;

    nil::crypto3::bench::run_fold_benchmark<Field>(bench_name("mul_lat"),
                                                   [](V& a, V const& b) { a *= b; });

    nil::crypto3::bench::run_independent_folds_benchmark<INDEPENDENT_FOLDS, Field>(
        bench_name("mul_thr"), [](V& a, V const& b) { a *= b; });

    nil::crypto3::bench::run_fold_benchmark<Field>(bench_name("add_lat"),
                                                   [](V& a, V const& b) { a += b; });

    nil::crypto3::bench::run_independent_folds_benchmark<INDEPENDENT_FOLDS, Field>(
        bench_name("add_thr"), [](V& a, V const& b) { a += b; });

    nil::crypto3::bench::run_fold_benchmark<Field>(bench_name("sub_lat"),
                                                   [](V& a, V const& b) { a -= b; });

    nil::crypto3::bench::run_independent_folds_benchmark<INDEPENDENT_FOLDS, Field>(
        bench_name("sub_thr"), [](V& a, V const& b) { a -= b; });

    nil::crypto3::bench::run_benchmark<Field>(bench_name("sqr"),
                                              [](V& a) { a.square_inplace(); });

    nil::crypto3::bench::run_benchmark<Field>(bench_name("inv"),
                                              [](V& a) { a = a.inversed(); });
}

using field_types = std::tuple<
    nil::crypto3::algebra::fields::alt_bn128_scalar_field<254u>,
    nil::crypto3::algebra::fields::goldilocks, nil::crypto3::algebra::fields::goldilocks_fp2, nil::crypto3::algebra::fields::mersenne31,
    nil::crypto3::algebra::fields::koalabear, nil::crypto3::algebra::fields::babybear,
    nil::crypto3::algebra::fields::babybear_fp4,
    nil::crypto3::algebra::fields::babybear_fp5,
    nil::crypto3::algebra::fields::pallas_base_field,
    nil::crypto3::algebra::fields::mnt4_base_field<298>,
    nil::crypto3::algebra::fields::mnt6_base_field<298>,
    nil::crypto3::algebra::fields::ed25519,
    nil::crypto3::algebra::fields::bls12_base_field<381u>,
    nil::crypto3::algebra::fields::bls12_scalar_field<381u>>;

BOOST_AUTO_TEST_CASE_TEMPLATE(field_operation_perf_test, Field, field_types) {
    run_perf_test<Field>(field_name<Field>());
}
