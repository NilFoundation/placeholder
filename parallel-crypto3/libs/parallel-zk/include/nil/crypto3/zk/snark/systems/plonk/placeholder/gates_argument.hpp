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
#include <ranges>
#include <unordered_map>

#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/static_simd_vector.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/centralized_expression_evaluator.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
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
                    using value_type = typename FieldType::value_type;

                    static constexpr std::size_t mini_chunk_size = 64;
                    using simd_vector_type =
                        math::static_simd_vector<value_type, mini_chunk_size>;

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

                    static inline std::vector<
                        std::pair<std::vector<std::pair<expression_evaluator_registration,
                                                        value_type>>,
                                  std::size_t>>
                    register_gate_argument_expressions(
                        const constraint_system_type& constraint_system,
                        central_evaluator_type& central_expr_evaluator,
                        const value_type& theta) {
                        PROFILE_SCOPE("Gate argument register constraints' expressions");

                        // Every constraint has variable type 'variable_type', but we want
                        // it to use 'polynomial_dfs_variable_type' instead.
                        // The only difference is the coefficient type inside a term. We
                        // want the coefficients to be dfs polynomials here.
                        auto value_type_to_polynomial_dfs =
                            [](const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };
                        expression_variable_type_converter<variable_type,
                                                           polynomial_dfs_variable_type>
                            converter(value_type_to_polynomial_dfs);

                        std::vector<
                            std::pair<std::vector<std::pair<
                                          expression_evaluator_registration, value_type>>,
                                      std::size_t>>
                            registrationss;

                        value_type theta_acc = value_type::one();

                        for (const auto& gate : constraint_system.gates()) {
                            std::vector<
                                std::pair<expression_evaluator_registration, value_type>>
                                registrations;
                            for (const auto& expr : gate.constraints) {
                                auto converted_expr = converter.convert(expr);
                                registrations.emplace_back(
                                    central_expr_evaluator.register_expression(
                                        std::move(converted_expr),
                                        gate.selector_index !=
                                            PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED),
                                    theta_acc);
                                theta_acc *= theta;
                            }
                            registrationss.emplace_back(std::move(registrations),
                                                        gate.selector_index);
                        }
                        return registrationss;
                    }

                    static inline std::array<polynomial_dfs_type, argument_size>
                    prove_eval(const constraint_system_type& constraint_system,
                               central_evaluator_type& central_expr_evaluator,
                               const value_type& theta) {
                        PROFILE_SCOPE("Gate argument prove eval");

                        std::vector<
                            std::pair<std::vector<std::pair<
                                          expression_evaluator_registration, value_type>>,
                                      std::size_t>>
                            registrationss = register_gate_argument_expressions(
                                constraint_system, central_expr_evaluator, theta);

                        central_expr_evaluator.evaluate_all();

                        std::size_t maximum_domain_size =
                            central_expr_evaluator.get_maximum_domain_size();

                        std::set<polynomial_dfs_variable_type> selectors_full;
                        std::set<polynomial_dfs_variable_type> selectors_half;

                        std::array<
                            std::vector<std::pair<
                                std::vector<std::pair<expression_evaluator_registration,
                                                      value_type>>,
                                std::size_t>>,
                            2>
                            registrationss_split;

                        for (const auto& [registrations, selector] : registrationss) {
                            std::vector<
                                std::pair<expression_evaluator_registration, value_type>>
                                registrations_full;
                            std::vector<
                                std::pair<expression_evaluator_registration, value_type>>
                                registrations_half;
                            for (const auto& registration : registrations) {
                                auto selector_var = polynomial_dfs_variable_type(
                                    selector, 0, false,
                                    polynomial_dfs_variable_type::column_type::selector);

                                bool full_degree =
                                    central_expr_evaluator
                                        .get_expression_value(registration.first)
                                        .size() ==
                                    central_expr_evaluator.get_maximum_domain_size();

                                if (selector !=
                                    PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                                    if (full_degree) {
                                        selectors_full.insert(selector_var);
                                    } else {
                                        selectors_half.insert(selector_var);
                                    }
                                }

                                if (full_degree) {
                                    registrations_full.push_back(registration);
                                } else {
                                    registrations_half.push_back(registration);
                                }
                            }
                            if (!registrations_full.empty()) {
                                registrationss_split[1].emplace_back(
                                    std::move(registrations_full), selector);
                            }
                            if (!registrations_half.empty()) {
                                registrationss_split[0].emplace_back(
                                    std::move(registrations_half), selector);
                            }
                        }

                        central_expr_evaluator.ensure_cache(selectors_full,
                                                            maximum_domain_size);
                        central_expr_evaluator.ensure_cache(selectors_half,
                                                            maximum_domain_size / 2);

                        PROFILE_SCOPE("Gate argument combine with theta and selectors");

                        std::array<polynomial_dfs_type, 2> F_split{
                            polynomial_dfs_type(maximum_domain_size / 2 - 1,
                                                maximum_domain_size / 2),
                            polynomial_dfs_type(maximum_domain_size - 1,
                                                maximum_domain_size)};

                        for (std::size_t full = 0; full <= 1; ++full) {
                            PROFILE_SCOPE(
                                "Gate argument combine with theta and selectors ({} "
                                "degree)",
                                full ? "full" : "half");
                            std::size_t current_size =
                                full ? maximum_domain_size : maximum_domain_size / 2;
                            wait_for_all(parallel_run_in_chunks<void>(
                                current_size,
                                [full, current_size, &F_split, &registrationss_split,
                                 &central_expr_evaluator,
                                 &theta](std::size_t begin, std::size_t end) {
                                    auto count =
                                        math::count_chunks<mini_chunk_size>(end - begin);
                                    for (std::size_t j = 0; j < count; ++j) {
                                        simd_vector_type combined_result{};
                                        for (const auto& [registrations, selector] :
                                             registrationss_split[full]) {
                                            simd_vector_type combined{};
                                            for (const auto& [registration, coefficient] :
                                                 registrations) {
                                                combined +=
                                                    math::get_chunk<mini_chunk_size>(
                                                        central_expr_evaluator
                                                            .get_expression_value(
                                                                registration),
                                                        begin, j) *
                                                    coefficient;
                                            }
                                            if (selector !=
                                                PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                                                auto selector_var =
                                                    polynomial_dfs_variable_type(
                                                        selector, 0, false,
                                                        polynomial_dfs_variable_type::
                                                            column_type::selector);
                                                combined *=
                                                    math::get_chunk<mini_chunk_size>(
                                                        *central_expr_evaluator.get(
                                                            selector_var, current_size),
                                                        begin, j);
                                            }
                                            combined_result += combined;
                                        }
                                        math::set_chunk<mini_chunk_size>(
                                            F_split[full], begin, j,
                                            std::move(combined_result));
                                    }
                                },
                                ThreadPool::PoolLevel::HIGH));
                        }
                        std::array<polynomial_dfs_type, argument_size> F;
                        F[0] = F_split[0];
                        F[0] += F_split[1];
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
