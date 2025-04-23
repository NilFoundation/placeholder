//---------------------------------------------------------------------------//
// Copyright (c) 2025 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE dag_expression_test

#include <iostream>
#include <variant>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/zk/math/dag_expression.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include "expression_generator.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::math;

template<typename VariableType>
std::unordered_map<VariableType, typename VariableType::assignment_type>
make_evaluation_map(
    const dag_expression<VariableType> &dag_expr
) {
    std::unordered_map<VariableType, typename VariableType::assignment_type> evaluation_map;
    using FieldType = typename VariableType::assignment_type::field_type;
    nil::crypto3::random::algebraic_engine<FieldType> alg_rnd_engine;
    auto visitor = [&evaluation_map, &alg_rnd_engine](const dag_node<VariableType> &node) {
        if (!std::holds_alternative<dag_variable<VariableType>>(node)) {
            return;
        }
        auto var_node = std::get<dag_variable<VariableType>>(node);
        evaluation_map[var_node.variable] = alg_rnd_engine();
    };
    dag_expr.visit_const(visitor);
    return evaluation_map;
}

BOOST_AUTO_TEST_CASE(dag_expression_test) {
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using var =
        typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    var w0(0, 0, var::column_type::witness);
    var w1(3, -1, var::column_type::public_input);
    var w2(4, 1, var::column_type::public_input);
    var w3(6, 2, var::column_type::constant);

    expression<var> expr =
        (w0 + w0 + w0) + 3 + (w0 + w1) * (w0 + w1) * (w0 + w1) * (w2 + w3 + 1) + w0 * w1 * (w2 + w3 + 1) * (w0 + w1);
    dag_expression<var> dag_expr;
    dag_expr.add_expression(expr);
    auto evaluation_map = make_evaluation_map(dag_expr);
    expression_evaluator<var> evaluator(
        expr,
        [&evaluation_map](const var &var) -> typename FieldType::value_type& {
            return evaluation_map[var];
        }
    );
    std::function<typename FieldType::value_type(const var &)> eval_map =
        [&evaluation_map](const var &var) -> typename FieldType::value_type {
            return evaluation_map[var];
        };

    // Evaluate call to Dag evaluates all the expressions, but stores the results inside.
    dag_expr.evaluate(eval_map);
    auto classic_result = evaluator.evaluate();
    BOOST_CHECK(classic_result == dag_expr.get_result(0));
}

BOOST_AUTO_TEST_CASE(dag_expression_test_random) {
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using value_type = typename FieldType::value_type;
    using var = typename nil::crypto3::zk::snark::plonk_variable<value_type>;

    boost::random::mt19937 random_engine = boost::random::mt19937(std::random_device()());
    auto expr = generate_random_constraint<var>(10, 10, random_engine);
    dag_expression<var> dag_expr;
    dag_expr.add_expression(expr);
    dag_expr.add_expression(expr);
    // note that while root nodes may evaluate duplicates, they should still be different
    BOOST_CHECK(dag_expr.root_nodes.size() == 2);
    auto evaluation_map = make_evaluation_map(dag_expr);
    std::function<value_type(const var &)> eval_map =
        [&evaluation_map](const var &var) -> typename FieldType::value_type {
            return evaluation_map[var];
        };
    // Evaluate call to Dag evaluates all the expressions, but stores the results inside.
    dag_expr.evaluate(eval_map);
    expression_evaluator<var> evaluator(
        expr,
        [&evaluation_map](const var &var) -> const typename FieldType::value_type& {
            return evaluation_map[var];
        }
    );
    auto classic_result = evaluator.evaluate();
    BOOST_CHECK(classic_result == dag_expr.get_result(0));
    BOOST_CHECK(classic_result == dag_expr.get_result(1));

    // also check that the child nodes are the same: we don't redo the computation
    BOOST_CHECK(dag_expr.root_nodes[0] == dag_expr.root_nodes[1]);
}

BOOST_AUTO_TEST_CASE(dag_expression_test_degree) {
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using var = typename nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    boost::random::mt19937 random_engine = boost::random::mt19937(std::random_device()());
    auto expr = generate_random_constraint<var>(10, 10, random_engine);
    dag_expression<var> dag_expr;
    dag_expr.add_expression(expr);

    expression_max_degree_visitor<var> visitor;
    std::size_t expr_degree = visitor.compute_max_degree(expr);
    std::size_t dag_degree = dag_expr.calc_degree();
    BOOST_CHECK(expr_degree == dag_degree);
}
