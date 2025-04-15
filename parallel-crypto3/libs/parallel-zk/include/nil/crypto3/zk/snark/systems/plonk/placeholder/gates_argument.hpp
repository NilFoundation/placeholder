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

#ifndef PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
#define PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP

#ifdef CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <iostream>
#include <memory>
#include <queue>
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

// TODO: check if we need next include.
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument {
                    using value_type = typename FieldType::value_type;

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<
                        transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
                    using variable_type = plonk_variable<value_type>;
                    using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;
                    using expression_type = expression<polynomial_dfs_variable_type>;
                    using central_evaluator_type = CentralAssignmentTableExpressionEvaluator<FieldType>;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;
                    using constraint_system_type = typename policy_type::constraint_system_type;

                    constexpr static const std::size_t argument_size = 1;

                    static inline size_t get_gate_argument_max_degree(
                            const constraint_system_type& constraint_system) {
                        size_t max_degree = 0;
                        math::expression_max_degree_visitor<variable_type> visitor;

std::cout << "Computing max degree of gate argument" << std::endl;
                        const auto& gates = constraint_system.gates();
                        for (const auto& gate : gates) {
                            for (const auto& constraint : gate.constraints) {
                                size_t constraint_degree = visitor.compute_max_degree(constraint);
std::cout << constraint << std::endl;
                                if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                                    constraint_degree += 1; // selector multiplication.
                                max_degree = std::max<size_t>(max_degree, constraint_degree);
                            }
                        }
                        return max_degree;
                    }

                    // Generates 2 expressions that need to be computed and sumed up to create the
                    // final polynomial.
                    static inline std::vector<expression_type> get_gate_argument_expressions(
                            const constraint_system_type& constraint_system,
                            const value_type& theta
                            ) {
                        PROFILE_SCOPE("Gate argument build expression");
                        std::vector<expression_type> expressions(2);

                        size_t max_degree = get_gate_argument_max_degree(constraint_system);
                        math::expression_max_degree_visitor<variable_type> visitor;

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        auto value_type_to_polynomial_dfs = [](
                            const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };
                        math::expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);

                        auto theta_acc = value_type::one();

                        const auto& gates = constraint_system.gates();
                        
                        for (const auto& gate : gates) {
                            std::vector<expression_type> gate_results(2);
                            for (const auto& constraint : gate.constraints) {
                                size_t constraint_degree = visitor.compute_max_degree(constraint);
                                if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                                    constraint_degree += 1; // selector multiplication.
                                
                                if (constraint_degree > max_degree / 2) {
                                    gate_results[0] += converter.convert(constraint * theta_acc);
                                } else {
                                    gate_results[1] += converter.convert(constraint * theta_acc);
                                }

                                theta_acc *= theta;
                            }

                            if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                                polynomial_dfs_variable_type selector(
                                    gate.selector_index, 0, false,
                                    polynomial_dfs_variable_type::column_type::selector);
                                gate_results[0] *= selector;
                                gate_results[1] *= selector;
                            }
                            expressions[0] += gate_results[0];
                            expressions[1] += gate_results[1];
                        }
                        return expressions;
                    }

                    static inline std::array<polynomial_dfs_type, argument_size>
                    prove_eval(
                        const constraint_system_type& constraint_system,
                        central_evaluator_type& central_expr_evaluator,
                        const value_type& theta
                    ) {
                        PROFILE_SCOPE("Gate argument prove eval");

                        std::vector<expression_type> exprs = get_gate_argument_expressions(constraint_system, theta);
std::cout << "Gate argument expressions are " << exprs[0] << std::endl << exprs[1] << std::endl;

                        central_expr_evaluator.register_expressions(exprs);
                        central_expr_evaluator.evaluate_all();

                        std::array<polynomial_dfs_type, argument_size> F;
                        F[0] = polynomial_dfs_type::zero();
                        for (const auto& expr: exprs) {
                            F[0] += central_expr_evaluator.get_expression_value(expr);
                        }
                        return F;
                    }

                    static inline std::array<value_type, argument_size>
                    verify_eval(
                        const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>>& gates,
                        typename policy_type::evaluation_map& evaluations,
                        const value_type& /*challenge*/,
                        value_type /*mask_value*/,
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
