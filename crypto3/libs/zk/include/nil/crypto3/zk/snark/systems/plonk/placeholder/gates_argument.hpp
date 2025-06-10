//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP

#include <iostream>
#include <memory>
#include <queue>
#include <ranges>
#include <unordered_map>

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/centralized_expression_evaluator.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/actor/core/parallelization_utils.hpp>
#include <nil/actor/core/thread_pool.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument {
                    using SmallFieldType = typename FieldType::small_subfield;
                    using value_type = typename FieldType::value_type;
                    using small_field_value_type = typename SmallFieldType::value_type;

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<
                        transcript_hash_type>;
                    using small_field_polynomial_dfs_type =
                        math::polynomial_dfs<small_field_value_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
                    using variable_type = plonk_variable<small_field_value_type>;
                    using polynomial_dfs_variable_type =
                        plonk_variable<polynomial_dfs_type>;
                    using small_field_polynomial_dfs_variable_type =
                        plonk_variable<small_field_polynomial_dfs_type>;
                    using expression_type =
                        expression<small_field_polynomial_dfs_variable_type>;
                    using central_evaluator_type =
                        CentralAssignmentTableExpressionEvaluator<SmallFieldType>;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;
                    using constraint_system_type = typename policy_type::constraint_system_type;

                    constexpr static const std::size_t argument_size = 1;

                    static inline size_t get_gate_argument_max_degree(
                            const constraint_system_type& constraint_system) {
                        size_t max_degree = 0;
                        expression_max_degree_visitor<variable_type> visitor;

                        const auto& gates = constraint_system.gates();
                        for (const auto& gate : gates) {
                            for (const auto& constraint : gate.constraints) {
                                size_t constraint_degree = visitor.compute_max_degree(constraint);
                                if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                                    constraint_degree += 1; // selector multiplication.
                                max_degree = std::max<size_t>(max_degree, constraint_degree);
                            }
                        }
                        return max_degree;
                    }

                    static constexpr std::size_t extension_dimension = FieldType::arity;

                    // Registers 2 arity-tuples of expressions that need to be computed
                    // and sumed up to create the final polynomial.
                    static inline std::array<std::array<expression_evaluator_registration,
                                                        extension_dimension>,
                                             2>
                    register_gate_argument_expressions(
                        const constraint_system_type& constraint_system,
                        central_evaluator_type& central_expr_evaluator,
                        const value_type& theta) {
                        PROFILE_SCOPE("Gate argument register expressions");
                        std::array<std::array<expression_type, extension_dimension>, 2>
                            expressions;

                        size_t max_degree = get_gate_argument_max_degree(constraint_system);
                        expression_max_degree_visitor<variable_type> visitor;

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        auto value_type_to_polynomial_dfs = [](
                            const typename variable_type::assignment_type& coeff) {
                                return small_field_polynomial_dfs_type(0, 1, coeff);
                            };
                        expression_variable_type_converter<variable_type, small_field_polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);

                        auto theta_acc = value_type::one();

                        const auto& gates = constraint_system.gates();

                        for (const auto& gate : gates) {
                            std::array<std::array<expression_type, extension_dimension>,
                                       2>
                                gate_results;
                            for (const auto& constraint : gate.constraints) {
                                size_t constraint_degree = visitor.compute_max_degree(constraint);
                                if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                                    constraint_degree += 1; // selector multiplication.

                                bool high_degree = constraint_degree > max_degree / 2;

                                auto converted = converter.convert(constraint);

                                for (std::size_t i = 0; i < extension_dimension; ++i) {
                                    gate_results[high_degree][i] += converted *
                                    value_type_to_polynomial_dfs(
                                        theta_acc.binomial_extension_coefficient(
                                            i));
                                }

                                theta_acc *= theta;
                            }

                            if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                                small_field_polynomial_dfs_variable_type selector(
                                    gate.selector_index, 0, false,
                                    small_field_polynomial_dfs_variable_type::column_type::selector);
                                for (std::size_t i = 0; i < extension_dimension; ++i) {
                                    gate_results[0][i] *= selector;
                                    gate_results[1][i] *= selector;
                                }
                            }
                            for (std::size_t i = 0; i < extension_dimension; ++i) {
                                expressions[0][i] += std::move(gate_results[0][i]);
                                expressions[1][i] += std::move(gate_results[1][i]);
                            }
                        }

                        std::array<std::array<expression_evaluator_registration,
                                              extension_dimension>,
                                   2>
                            registrations;

                        for (std::size_t i = 0; i < extension_dimension; ++i) {
                            registrations[0][i] =
                                central_expr_evaluator.register_expression(
                                    expressions[0][i]);
                            registrations[1][i] =
                                central_expr_evaluator.register_expression(
                                    expressions[1][i]);
                        }
                        return registrations;
                    }

                    static inline std::array<polynomial_dfs_type, argument_size>
                    prove_eval(
                        const constraint_system_type& constraint_system,
                        central_evaluator_type& central_expr_evaluator,
                        const value_type& theta
                    ) {
                        TAGGED_PROFILE_SCOPE("{high level} gate",
                                             "Gate argument prove eval");

                        auto registrations = register_gate_argument_expressions(
                            constraint_system, central_expr_evaluator, theta);

                        central_expr_evaluator.evaluate_all();


                        std::array<polynomial_dfs_type, argument_size> F;

                        TAGGED_PROFILE_SCOPE("{low level} expr eval big field",
                                             "Combine evaluation results");
                        for (const auto& registration : registrations) {
                            std::array<small_field_polynomial_dfs_type*,
                                       extension_dimension>
                                coefficients;
                            for (std::size_t i = 0; i < extension_dimension; ++i) {
                                coefficients[i] =
                                    &central_expr_evaluator.get_expression_value(
                                        registration[i]);
                            }
                            auto combined =
                                polynomial_dfs_type::extension_from_coefficients(
                                    coefficients);
                            F[0] += std::move(combined);
                        }
                        return F;
                    }

                    static inline std::array<value_type, argument_size> verify_eval(
                        const std::vector<plonk_gate<
                            SmallFieldType, plonk_constraint<SmallFieldType>>>& gates,
                        typename policy_type::evaluation_map& evaluations,
                        const value_type& /*challenge*/, value_type /*mask_value*/,
                        transcript_type& transcript) {
                        value_type theta =
                            transcript.template challenge<FieldType>();

                        std::array<value_type, argument_size> F;

                        value_type theta_acc = value_type::one();

                        for (const auto& gate : gates) {
                            value_type gate_result = value_type::zero();

                            for (const auto& constraint : gate.constraints) {
                                gate_result += constraint.evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int, typename plonk_variable<value_type>::column_type>
                                selector_key = std::make_tuple(
                                    gate.selector_index, 0,
                                    plonk_variable<value_type>::column_type::selector);

                            gate_result *= evaluations[selector_key];

                            F[0] += gate_result;
                        }

                        return F;
                    }

                    static inline void fill_challenge_queue(
                        transcript_type &transcript,
                        std::queue<value_type>& queue) {
                        // Theta
                        queue.push(transcript.template challenge<FieldType>());
                    }
                };
            }  // namespace snark
        }  // namespace zk
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
