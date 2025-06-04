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

#ifndef CRYPTO3_ZK_CENTRAL_EXPRESSION_EVALUATOR_HPP
#define CRYPTO3_ZK_CENTRAL_EXPRESSION_EVALUATOR_HPP

#include <stdexcept>
#include <vector>

#include <nil/actor/core/parallelization_utils.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>

#include <nil/crypto3/zk/math/cached_assignment_table.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/dag_expression.hpp>
#include <nil/crypto3/zk/math/dag_expression_evaluator.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

namespace nil::crypto3::zk::snark {

    using expression_evaluator_registration = std::size_t;

    // This class is responsible for returning the values of assignment table in the required sizes, re-using the values
    // by storing them in a cache. It also allows to register expressions and later get the values of those expressions.
    // Expressions will be computed in 2 sizes, those with Maximal degree N will be computed together, while everying of degree
    // < N / 2 will be computed separately.
    template<typename FieldType>
    class CentralAssignmentTableExpressionEvaluator {
      public:
        enum class State : std::uint8_t{
            ADDING_EXPRESSIONS = 0,  // Currently adding expressions
            EVALUATED = 1            // Evaluation has completed
        };

        enum class DAG_Type : std::uint8_t{
            MAX_DEGREE = 0,
            HALF_DEGREE = 1
        };

        using value_type = typename FieldType::value_type;
        using polynomial_type = math::polynomial<value_type>;
        using polynomial_dfs_type = math::polynomial_dfs<value_type>;
        using cached_assignment_table_type = cached_assignment_table<FieldType>;

        static constexpr std::size_t mini_chunk_size = 64;
        using variable_type = plonk_variable<value_type>;
        using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;
        using expr_type = expression<polynomial_dfs_variable_type>;

        CentralAssignmentTableExpressionEvaluator(
                std::shared_ptr<plonk_polynomial_dfs_table<FieldType>> polynomial_table,
                const polynomial_dfs_type& mask_assignment,
                const polynomial_dfs_type& lagrange_0)
            : _cached_assignment_table(polynomial_table, mask_assignment, lagrange_0)
            , _state(State::ADDING_EXPRESSIONS) {}

        // Call to this function must resize all the columns to size D * degree, where D is the size of original domain.
        void cache_all_columns_for_degree(size_t degree) {
            _cached_assignment_table.cache_all_columns_for_degree(degree);
        }

        void ensure_cache(const std::set<polynomial_dfs_variable_type>& variables,
                          std::size_t size) {
            _cached_assignment_table.ensure_cache(variables, size);
        }

        // Rememebers the expression to evaluate later.
        [[nodiscard]] expression_evaluator_registration register_expression(
            const expr_type& expr) {
            if (_state != State::ADDING_EXPRESSIONS) {
                throw std::logic_error("Can't add expressions after evaluation is done.");
            }
            _registered_exprs.emplace_back(expr);
            return _registered_exprs.size() - 1;
        }

        // Call to this function will drop all the expressions registered and starting again. Only the
        // precomputed cache of assignment table will be kept.
        void reset_expressions() {
            _dag_expr_full_degree = dag_expression<polynomial_dfs_variable_type>();
            _dag_expr_half_degree = dag_expression<polynomial_dfs_variable_type>();

            _registered_exprs.clear();
            _registration_to_result_id_map.clear();
            _results_half_degree.clear();
            _results_full_degree.clear();
            _state = State::ADDING_EXPRESSIONS;
        }

        // You should call this only once and after all expressions have been registered.
        // Returns all expression values in the same order as they were registered.
        void evaluate_all() {
            PROFILE_SCOPE("Central evaluate all");
            if (_state != State::ADDING_EXPRESSIONS) {
                throw std::logic_error("Can't evaluate again after evaluation is done.");
            }
            _state = State::EVALUATED;

            // TODO(martun): optimize the expressions here, before converting to a DAG!

            std::size_t max_degree = std::max<std::size_t>(get_max_degree(), 2);
            // Round the max degree up to nearest power of 2.
            max_degree = std::pow(2, ceil(std::log2(max_degree)));

            // Collect all the variables used in full degree and half degree expressions,
            // so later we can prepare the cache.
            std::set<polynomial_dfs_variable_type> variables_set_half_degree;
            std::set<polynomial_dfs_variable_type> variables_set_full_degree;
            expression_for_each_variable_visitor<polynomial_dfs_variable_type> half_degree_visitor(
                [&variables_set_half_degree](const polynomial_dfs_variable_type& var) {
                    variables_set_half_degree.insert(var);
            });
            expression_for_each_variable_visitor<polynomial_dfs_variable_type> full_degree_visitor(
                [&variables_set_full_degree](const polynomial_dfs_variable_type& var) {
                    variables_set_full_degree.insert(var);
            });

            dag_expression_builder<polynomial_dfs_variable_type>
                _dag_expr_builder_half_degree;
            dag_expression_builder<polynomial_dfs_variable_type>
                _dag_expr_builder_full_degree;

            _registration_to_result_id_map.resize(_registered_exprs.size());

            // Split expressions into 2 sets, those with degree <= D/2, and the rest.
            for (std::size_t i = 0; i < _registered_exprs.size(); ++i) {
                const auto& expr = _registered_exprs[i];
                std::size_t degree = _max_degree_visitor.compute_max_degree(expr);
                if (degree <= max_degree / 2) {
                    _dag_expr_builder_half_degree.add_expression(expr);
                    half_degree_visitor.visit(expr);
                    _registration_to_result_id_map[i] = {
                        DAG_Type::HALF_DEGREE,
                        _dag_expr_builder_half_degree.get_expression_count() - 1};
                } else {
                    _dag_expr_builder_full_degree.add_expression(expr);
                    full_degree_visitor.visit(expr);
                    _registration_to_result_id_map[i] = {
                        DAG_Type::MAX_DEGREE,
                        _dag_expr_builder_full_degree.get_expression_count() - 1};
                }
            }

            // Create both DAGs.
            _dag_expr_full_degree = _dag_expr_builder_full_degree.build();
            _dag_expr_half_degree = _dag_expr_builder_half_degree.build();

            // Prepare the cache for calculation, precompute all variable values in required sizes.
            const size_t extended_domain_size = _cached_assignment_table.get_original_domain_size() * max_degree;
            _cached_assignment_table.ensure_cache(variables_set_half_degree, extended_domain_size / 2);
            _cached_assignment_table.ensure_cache(variables_set_full_degree, extended_domain_size);

            // Compute and store all the expression values.
            dag_expression_evaluator<FieldType> half_degree_evaluator(_dag_expr_half_degree, max_degree / 2);
            _results_half_degree = half_degree_evaluator.evaluate(_cached_assignment_table);
            dag_expression_evaluator<FieldType> max_degree_evaluator(_dag_expr_full_degree, max_degree);
            _results_full_degree = max_degree_evaluator.evaluate(_cached_assignment_table);
        }

        std::shared_ptr<polynomial_dfs_type> get(const variable_type &v, std::size_t size) {
            return _cached_assignment_table.get(v, size);
        }

        size_t get_original_domain_size() const {
            return _cached_assignment_table.get_original_domain_size();
        }

        // Returns the value of given expression. You cannot call this before calling evaluate_all.
        polynomial_dfs_type& get_expression_value(
            const expression_evaluator_registration& registration) {
            if (_state != State::EVALUATED) {
                throw std::logic_error("Can't return expression value before evaluation is done.");
            }
            auto [dag_type, index] = _registration_to_result_id_map.at(registration);
            if (dag_type == DAG_Type::HALF_DEGREE) {
                return _results_half_degree.at(index);
            }
            return _results_full_degree.at(index);
        }

        // You can call this function to free up some memory.
        void erase_expression_value(
            const expression_evaluator_registration& registartion) {
            if (_state != State::EVALUATED) {
                throw std::logic_error("Can't erase expression value before evaluation is done.");
            }
            auto [dag_type, index] = _registration_to_result_id_map.at(registartion);
            if (dag_type == DAG_Type::HALF_DEGREE)
                _results_half_degree[index] = polynomial_dfs_type();
            else
                _results_full_degree[index] = polynomial_dfs_type();
        }

      private:
        std::size_t get_max_degree() const {
            std::size_t max_degree = 0;
            for (const auto& expr : _registered_exprs) {
                std::size_t degree = _max_degree_visitor.compute_max_degree(expr);
                max_degree = std::max<std::size_t>(max_degree, degree);
            }
            return max_degree;
        }

        State _state;
        cached_assignment_table_type _cached_assignment_table;

        // We will have 2 separate DAGs, one for expressions with degree > N / 2,
        // another for expression of degree <= N/2, where N is maximal degree of any expression.
        dag_expression<polynomial_dfs_variable_type> _dag_expr_full_degree;
        dag_expression<polynomial_dfs_variable_type> _dag_expr_half_degree;

        // We store all registered expressions to be able to compute maximal degree 'max_degree' from it.
        std::vector<expr_type> _registered_exprs;

        // For each registered expression, before the evaluation we will link it to the DAG and the number of
        // result inside that DAG.
        std::vector<std::pair<DAG_Type, size_t>> _registration_to_result_id_map;

        // TODO(martun): change these to shared_ptr, so we don't need to copy much.
        // Contains computation results for each expression of degree <= D/2.
        std::vector<polynomial_dfs_type> _results_half_degree;
        // Contains computation results for each expression of degree > D/2.
        std::vector<polynomial_dfs_type> _results_full_degree;

        // Used to compute the maximal degree of a given expression.
        expression_max_degree_visitor<polynomial_dfs_variable_type> _max_degree_visitor;

        // We need a zero, because sometimes we are asked to evaluate an empty expression.
        polynomial_dfs_type zero = polynomial_dfs_type::zero();
    };

} // namespace nil::crypto3::zk::snark

#endif // CRYPTO3_ZK_CENTRAL_EXPRESSION_EVALUATOR_HPP
