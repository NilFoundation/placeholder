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

#define BOOST_TEST_MODULE dag_expression_evaluator_test

#include <iostream>
#include <variant>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/math/cached_assignment_table.hpp>
#include <nil/crypto3/zk/math/dag_expression.hpp>
#include <nil/crypto3/zk/math/dag_expression_evaluator.hpp>

#include <nil/crypto3/test_tools/random_test_initializer.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(dag_expression_evaluator_test_suite)

BOOST_AUTO_TEST_CASE(dag_expression_evaluator_test) {
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using value_type = typename FieldType::value_type;
    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
    using var = plonk_variable<polynomial_dfs_type>;
    using cached_assignment_table_type = cached_assignment_table<FieldType>;

    test_tools::random_test_initializer<FieldType> random_test_initializer;


    using private_table_type = plonk_polynomial_dfs_table<FieldType>::private_table_type;
    using public_table_type = plonk_polynomial_dfs_table<FieldType>::public_table_type;

    polynomial_dfs_type w0_value = {1,
        {0x3_big_uint255, 
         0x7_big_uint255}};

    polynomial_dfs_type w1_value = {1,
        {0x7_big_uint255,
         0x6_big_uint255}};

    std::vector<polynomial_dfs_type> witness_values = {w0_value, w1_value};

    std::shared_ptr<private_table_type> private_table = std::make_shared<private_table_type>(witness_values);
    std::shared_ptr<public_table_type> public_table = std::make_shared<public_table_type>();

    auto polynomial_table = std::make_shared<plonk_polynomial_dfs_table<FieldType>>(private_table, public_table);
    size_t domain_size = polynomial_table->witness_column_size(0);
    std::shared_ptr<math::evaluation_domain<FieldType>> domain = math::make_evaluation_domain<FieldType>(
        polynomial_table->witness_column_size(0));

    // We don't care about the following values in this test, they are only used in selector values.
    // Just make sure they have the same size as variable values.
    polynomial_dfs_type mask_assignment(1, 2); 
    polynomial_dfs_type lagrange_0(1, 2);
    cached_assignment_table_type table(polynomial_table, mask_assignment, lagrange_0);

    // Now run the DAG evaluator.
    var w0(0, 0, var::column_type::witness);
    var w1(1, 0, var::column_type::witness);

    expression<var> expr = w0 * w1;
    dag_expression_builder<var> dag_expr_builder;
    dag_expr_builder.add_expression(expr);
    dag_expression<var> dag_expr = dag_expr_builder.build();

    table.ensure_cache({w0, w1}, domain_size * 2);

    dag_expression_evaluator<FieldType> dag_evaluator(dag_expr, 2);
    std::vector<polynomial_dfs_type> result = dag_evaluator.evaluate(table);
    auto classic_result = polynomial_table->get_variable_value(w0, domain) * polynomial_table->get_variable_value(w1, domain);

    // We will compare the coefficients here, because the results have different degrees.
    BOOST_CHECK(classic_result.coefficients() == result[0].coefficients());
}

BOOST_AUTO_TEST_SUITE_END()
