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

#ifndef PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_EVALUATOR_HPP
#define PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_EVALUATOR_HPP

#ifdef CRYPTO3_ZK_MATH_DAG_EXPRESSION_EVALUATOR_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <stdexcept>
#include <vector>
#include <functional>
#include <variant>
#include <stack>

#include <boost/bimap/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/container/small_vector.hpp>

#include <nil/crypto3/math/polynomial/static_simd_vector.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/dag_expression.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil::crypto3::zk::snark {
    
    template<typename FieldType>
    struct dag_expression_evaluator {
        using value_type = typename FieldType::value_type;
        using polynomial_type = math::polynomial<value_type>;
        using polynomial_dfs_type = math::polynomial_dfs<value_type>;
        using cached_assignment_table_type = dfs_cache<FieldType>;

        static constexpr std::size_t mini_chunk_size = 64;
        using simd_vector_type = math::static_simd_vector<
            value_type, mini_chunk_size>;
        using variable_type = plonk_variable<value_type>;
        using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;
        using simd_vector_variable_type = plonk_variable<simd_vector_type>;

        dag_expression_evaluator(const dag_expression<polynomial_dfs_variable_type>& expr, size_t max_degree)
            : _expr(expr)
            , _max_degree(max_degree) {}

        simd_vector_type get_variable_value_chunk(
                const cached_assignment_table_type& _cached_assignment_table,
                const simd_vector_variable_type& var,
                size_t extended_domain_size,
                size_t begin, size_t j) {
            return math::get_chunk<mini_chunk_size>(
                *_cached_assignment_table.get(var, extended_domain_size), begin, j);
        }

        /** \Brief Computes the evaluation results of all the expressions.
         *  We must take care about converting everything we need to a simd type and parallelize here.
         *  The provided cache must already contain all the required variables in the required sizes.
         */
        std::vector<polynomial_dfs_type> evaluate(const cached_assignment_table_type& _cached_assignment_table) {
            const size_t extended_domain_size = _cached_assignment_table.original_domain_size * _max_degree;

            // Create empty dfs polynomials of degree 'extended_domain_size - 1' and size 'extended_domain_size'.
            std::vector<polynomial_dfs_type> result(_expr.get_root_nodes_count(),
                polynomial_dfs_type(extended_domain_size - 1, extended_domain_size));

            wait_for_all(parallel_run_in_chunks<void>(
                extended_domain_size,
                [this, &_cached_assignment_table, &result, extended_domain_size](
                    std::size_t begin, std::size_t end) {
                    auto count = math::count_chunks<mini_chunk_size>(end - begin);

                    std::vector<simd_vector_type> assignment_segments(this->_expr.get_nodes_count());
                    for (std::size_t j = 0; j < count; ++j) {
                        this->compute_dag_segment_values(
                            assignment_segments, _cached_assignment_table, extended_domain_size, begin, j);

                        for (std::size_t k = 0; k < this->_expr.get_root_nodes_count(); ++k) {
                            math::set_chunk(result[k], begin, j, assignment_segments[this->_expr.get_root_node(k)]);
                        }
                    }
                },
                ThreadPool::PoolLevel::HIGH
            ));

            return result;
        }

    private:

        // TODO(martun): change this function to use a visitor class.
        /** \brief Computes all the values of DAG assignments for the given segment.
         *  This function is called from multiple threads
         *  to compute the final results for the whole DAG.
         *
         *  \param[out] assignment_segments - Computed values for the current segment for each DAG node.
         */
        void compute_dag_segment_values(std::vector<simd_vector_type>& assignment_segments,
                                        const cached_assignment_table_type& _cached_assignment_table,
                                        size_t extended_domain_size, size_t begin, size_t j) {
            size_t k = 0;
            for (const auto& [node, index] : _expr.get_node_map().right) {
                if (std::holds_alternative<dag_constant<polynomial_dfs_variable_type>>(node)) {
                    assignment_segments[k] = math::get_chunk<mini_chunk_size>(
                            std::get<dag_constant<polynomial_dfs_variable_type>>(node).value, begin, j);
                } else if (std::holds_alternative<dag_variable<polynomial_dfs_variable_type>>(node)) {
                    assignment_segments[k] = get_variable_value_chunk(
                        _cached_assignment_table,
                        std::get<dag_variable<polynomial_dfs_variable_type>>(node).variable,
                        extended_domain_size, begin, j);
                } else if (std::holds_alternative<dag_addition>(node)) {
                    const auto& add = std::get<dag_addition>(node);
                    assignment_segments[k] = assignment_segments[add.operands[0]];
                    for (std::size_t i = 1; i < add.operands.size(); i++) {
                        assignment_segments[k] += assignment_segments[add.operands[i]];
                    }
                } else if (std::holds_alternative<dag_multiplication>(node)) {
                    const auto& mul = std::get<dag_multiplication>(node);
                    assignment_segments[k] = assignment_segments[mul.operands[0]];
                    for (std::size_t i = 1; i < mul.operands.size(); i++) {
                        assignment_segments[k] *= assignment_segments[mul.operands[i]];
                    }
                } else if (std::holds_alternative<dag_negation>(node)) {
                    assignment_segments[k] = 
                        -assignment_segments[std::get<dag_negation>(node).operand];
                }
                ++k;
            }
        }

        dag_expression<polynomial_dfs_variable_type> _expr;
        size_t _max_degree;
    };

} // namespace nil::crypto3::zk::snark

#endif // PARALLEL_CRYPTO3_ZK_MATH_DAG_EXPRESSION_EVALUATOR_HPP
