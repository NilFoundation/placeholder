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

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/polynomial/static_simd_vector.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/dag_expression.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/actor/core/parallelization_utils.hpp>
#include <nil/actor/core/thread_pool.hpp>
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType,
                         std::size_t ArgumentSize = 1>
                struct placeholder_gates_argument;

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument<FieldType, ParamsType, 1> {
                    static constexpr std::size_t mini_chunk_size = 16;
                    typedef
                        typename ParamsType::transcript_hash_type transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<
                        transcript_hash_type>;
                    using polynomial_dfs_type =
                        math::polynomial_dfs<typename FieldType::value_type>;
                    using simd_vector_type =
                        math::static_simd_vector<typename FieldType::value_type,
                                                 mini_chunk_size>;
                    using variable_type = plonk_variable<typename FieldType::value_type>;
                    using polynomial_dfs_variable_type =
                        plonk_variable<polynomial_dfs_type>;
                    using simd_vector_variable_type = plonk_variable<simd_vector_type>;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t argument_size = 1;

                    static inline void build_variable_value_map(
                        const math::expression<simd_vector_variable_type>& expr,
                        const plonk_polynomial_dfs_table<FieldType>& assignments,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                        std::size_t extended_domain_size,
                        std::unordered_map<simd_vector_variable_type,
                                           polynomial_dfs_type>& variable_values_out,
                        const polynomial_dfs_type& mask_polynomial,
                        const polynomial_dfs_type& lagrange_0) {
                        PROFILE_SCOPE("Gate argument build variable value map");

                        std::vector<simd_vector_variable_type> variables;

                        math::expression_for_each_variable_visitor<
                            simd_vector_variable_type>
                            visitor([&variables, &variable_values_out](
                                        const simd_vector_variable_type& var) {
                                // Create the structure of the map, so its values can be filled in parallel.
                                if (variable_values_out.find(var) == variable_values_out.end()) {
                                    variables.push_back(var);
                                    variable_values_out[var] = polynomial_dfs_type::zero();
                                }
                            });

                        visitor.visit(expr);

                        std::shared_ptr<math::evaluation_domain<FieldType>>
                            extended_domain = math::make_evaluation_domain<FieldType>(
                                extended_domain_size);

                        parallel_for(
                            0, variables.size(),
                            [&variables, &variable_values_out, &assignments, &domain,
                             &extended_domain, extended_domain_size, &mask_polynomial,
                             &lagrange_0](std::size_t i) {
                                const simd_vector_variable_type& var = variables[i];

                                // Convert the variable to polynomial_dfs variable type.
                                polynomial_dfs_variable_type var_dfs(
                                    var.index, var.rotation, var.relative,
                                    static_cast<typename polynomial_dfs_variable_type::
                                                    column_type>(
                                        static_cast<std::uint8_t>(var.type)));

                                polynomial_dfs_type assignment;
                                if (var.index ==
                                        PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED &&
                                    var.type == simd_vector_variable_type::column_type::
                                                    selector) {
                                    assignment = mask_polynomial;
                                } else if (
                                    var.index ==
                                        PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED &&
                                    var.type == simd_vector_variable_type::column_type::
                                                    selector) {
                                    assignment = mask_polynomial - lagrange_0;
                                } else if (var.index ==
                                               PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED &&
                                           var.type == simd_vector_variable_type::
                                                           column_type::selector) {
                                    assignment = polynomial_dfs_type::one();
                                } else {
                                    assignment =
                                        assignments.get_variable_value(var_dfs, domain);
                                }

                                // In parallel version we always resize the assignment
                                // poly, it's better for parallelization. if (count > 1) {
                                assignment.resize(extended_domain_size, domain,
                                                  extended_domain);
                                variable_values_out[var] = std::move(assignment);
                            }, ThreadPool::PoolLevel::HIGH);

                        SCOPED_LOG("Variables count: {}", variable_values_out.size());
                    }

                    static inline std::array<polynomial_dfs_type, argument_size>
                    prove_eval(
                        const typename policy_type::constraint_system_type&
                            constraint_system,
                        const plonk_polynomial_dfs_table<FieldType>& column_polynomials,
                        std::shared_ptr<math::evaluation_domain<FieldType>>
                            original_domain,
                        std::uint32_t max_gates_degree,
                        const polynomial_dfs_type &mask_polynomial,
                        const polynomial_dfs_type &lagrange_0,
                        transcript_type& transcript
                    ) {
                        using value_type = typename FieldType::value_type;
                        PROFILE_SCOPE("Gate argument prove eval");

                        // max_gates_degree that comes from the outside does not take into
                        // account multiplication by selector.
                        ++max_gates_degree;
                        value_type theta =
                            transcript.template challenge<FieldType>();

                        auto value_type_to_simd_vector =
                            [](const typename variable_type::assignment_type& coeff) {
                                return simd_vector_type(coeff);
                            };

                        std::vector<std::uint32_t> extended_domain_sizes;
                        std::vector<std::uint32_t> degree_limits;
                        std::uint32_t max_degree =
                            std::pow(2, ceil(std::log2(max_gates_degree)));
                        std::uint32_t max_domain_size = original_domain->m * max_degree;

                        SCOPED_LOG(
                            "Gate argument max degree: {}, small domain max "
                            "degree: {}, original domain size: {}",
                            max_degree, max_degree / 2, original_domain->m);

                        degree_limits.push_back(max_degree);
                        extended_domain_sizes.push_back(max_domain_size);
                        degree_limits.push_back(max_degree / 2);
                        extended_domain_sizes.push_back(max_domain_size / 2);

                        std::vector<math::expression<simd_vector_variable_type>>
                            expressions(extended_domain_sizes.size());
                        auto theta_acc = FieldType::value_type::one();

                        math::expression_variable_type_converter<
                            variable_type, simd_vector_variable_type>
                            converter(value_type_to_simd_vector);

                        math::expression_max_degree_visitor<variable_type> visitor;

                        std::vector<std::size_t> constraint_counts(
                            extended_domain_sizes.size());

                        const auto& gates = constraint_system.gates();
                        {
                            PROFILE_SCOPE("Gate argument build expression");
                            for (const auto& gate : gates) {
                                std::vector<math::expression<simd_vector_variable_type>>
                                    gate_results(extended_domain_sizes.size());
                                for (const auto& constraint : gate.constraints) {
                                    auto next_term = converter.convert(constraint) *
                                                     value_type_to_simd_vector(theta_acc);

                                    theta_acc *= theta;

                                    size_t constraint_degree = visitor.compute_max_degree(constraint);
                                    if (gate.selector_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED)
                                        constraint_degree += 1; // selector multiplication.

                                    for (int i = extended_domain_sizes.size() - 1; i >= 0; --i) {
                                        // Whatever the degree of term is, add it to the maximal degree expression.
                                        if (degree_limits[i] >= constraint_degree || i == 0) {
                                            gate_results[i] += next_term;
                                            ++constraint_counts[i];
                                            break;
                                        }
                                    }
                                }

                                simd_vector_variable_type selector =
                                    simd_vector_variable_type(
                                        gate.selector_index, 0, false,
                                        simd_vector_variable_type::column_type::selector);
                                for (size_t i = 0; i < extended_domain_sizes.size();
                                     ++i) {
                                    gate_results[i] *= selector;
                                    expressions[i] += gate_results[i];
                                }
                            }
                        }

                        std::array<polynomial_dfs_type, argument_size> F;
                        F[0] = polynomial_dfs_type::zero();
                        for (std::size_t i = 0; i < extended_domain_sizes.size(); ++i) {
                            PROFILE_SCOPE("Gate argument evaluation on domain #{}",
                                          i + 1);
                            SCOPED_LOG("Constraint count: {}", constraint_counts[i]);
                            std::unordered_map<simd_vector_variable_type,
                                               polynomial_dfs_type>
                                variable_values;

                            build_variable_value_map(
                                expressions[i], column_polynomials, original_domain,
                                extended_domain_sizes[i], variable_values,
                                mask_polynomial, lagrange_0);

                            math::dag_expression<simd_vector_variable_type> dag_expr(
                                expressions[i]);

                            polynomial_dfs_type result(extended_domain_sizes[i] - 1,
                                                       extended_domain_sizes[i]);

                            {
                                PROFILE_SCOPE("Gate argument expression evaluation");

                                wait_for_all(parallel_run_in_chunks<void>(
                                    extended_domain_sizes[i],
                                    [&variable_values, &result, &dag_expr](
                                        std::size_t begin, std::size_t end) {
                                        auto dag_expr_copy = dag_expr;
                                        auto count = math::count_chunks<mini_chunk_size>(
                                            end - begin);
                                        for (std::size_t j = 0; j < count; ++j) {
                                            std::function<simd_vector_type(
                                                const simd_vector_variable_type&)>
                                                eval_map =
                                                    [&variable_values, begin, end,
                                                     j](const simd_vector_variable_type&
                                                            var) -> simd_vector_type {
                                                return math::get_chunk<mini_chunk_size>(
                                                    variable_values[var], begin, j);
                                            };
                                            auto chunk_result =
                                                dag_expr_copy.evaluate(eval_map)[0];
                                            math::set_chunk(result, begin, j,
                                                            chunk_result);
                                        }
                                    },
                                    ThreadPool::PoolLevel::HIGH));
                            }

                            PROFILE_SCOPE("Gate argument add to result");

                            F[0] += result;
                        }

                        return F;
                    }

                    static inline std::array<typename FieldType::value_type,
                                             argument_size>
                    verify_eval(
                        const std::vector<
                            plonk_gate<FieldType, plonk_constraint<FieldType>>>& gates,
                        typename policy_type::evaluation_map& evaluations,
                        const typename FieldType::value_type& /*challenge*/,
                        typename FieldType::value_type /*mask_value*/,
                        transcript_type& transcript) {
                        typename FieldType::value_type theta =
                            transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc =
                            FieldType::value_type::one();

                        for (const auto& gate : gates) {
                            typename FieldType::value_type gate_result =
                                FieldType::value_type::zero();

                            for (const auto& constraint : gate.constraints) {
                                gate_result +=
                                    constraint.evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int,
                                       typename plonk_variable<
                                           typename FieldType::value_type>::column_type>
                                selector_key = std::make_tuple(
                                    gate.selector_index, 0,
                                    plonk_variable<typename FieldType::value_type>::
                                        column_type::selector);

                            gate_result *= evaluations[selector_key];

                            F[0] += gate_result;
                        }

                        return F;
                    }

                    static inline void fill_challenge_queue(
                        transcript_type &transcript,
                        std::queue<typename FieldType::value_type>& queue) {
                        // Theta
                        queue.push(transcript.template challenge<FieldType>());
                    }
                };
            }  // namespace snark
        }  // namespace zk
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
