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

#include <unordered_map>
#include <iostream>
#include <memory>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType, std::size_t ArgumentSize = 1>
                struct placeholder_gates_argument;

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument<FieldType, ParamsType, 1> {

                    typedef typename ParamsType::transcript_hash_type transcript_hash_type;
                    using value_type = typename FieldType::value_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
                    using variable_type = plonk_variable<value_type>;
                    using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t argument_size = 1;
#ifndef GPU_PROVER
                    static inline void build_variable_value_map(
                        const math::expression<variable_type>& expr,
                        const plonk_polynomial_dfs_table<FieldType>& assignments,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                        std::size_t extended_domain_size,
                        std::unordered_map<variable_type, polynomial_dfs_type>& variable_values_out,
                        const polynomial_dfs_type &mask_polynomial,
                        const polynomial_dfs_type &lagrange_0
                    ) {

                        std::unordered_map<variable_type, size_t> variable_counts;
                        std::vector<variable_type> variables;

                        math::expression_for_each_variable_visitor<variable_type> visitor(
                            [&variable_counts, &variables, &variable_values_out](const variable_type& var) {
                                // Create the structure of the map so we can change the values later.
                                if (variable_counts[var] == 0) {
                                    variables.push_back(var);
                                    // Create the structure of the map, so its values can be filled in parallel.
                                    if (variable_values_out.find(var) == variable_values_out.end()) {
                                        variable_values_out[var] = polynomial_dfs_type();
                                    }
                                }
                                variable_counts[var]++;
                        });

                        visitor.visit(expr);

                        std::shared_ptr<math::evaluation_domain<FieldType>> extended_domain =
                            math::make_evaluation_domain<FieldType>(extended_domain_size);

                        parallel_for(0, variables.size(),
                            [&variables, &variable_values_out, &assignments, &domain, &extended_domain, extended_domain_size, &mask_polynomial, &lagrange_0](std::size_t i) {
                                const variable_type& var = variables[i];

                                // Convert the variable to polynomial_dfs variable type.
                                polynomial_dfs_variable_type var_dfs(var.index, var.rotation, var.relative,
                                    static_cast<typename polynomial_dfs_variable_type::column_type>(
                                        static_cast<std::uint8_t>(var.type)));

                                polynomial_dfs_type assignment;
                                if( var.index == PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED && var.type == variable_type::column_type::selector){
                                    assignment = mask_polynomial;
                                } else if( var.index == PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED && var.type == variable_type::column_type::selector) {
                                    assignment = mask_polynomial - lagrange_0;
                                } else
                                    assignment = assignments.get_variable_value(var_dfs, domain);

                                // In parallel version we always resize the assignment poly, it's better for parallelization.
                                // if (count > 1) {
                                assignment.resize(extended_domain_size, domain, extended_domain);
                                variable_values_out[var] = std::move(assignment);
                            }, ThreadPool::PoolLevel::HIGH);
                    }

                    static inline std::array<polynomial_dfs_type, argument_size> prove_eval(
                        const typename policy_type::constraint_system_type &constraint_system,
                        const plonk_polynomial_dfs_table<FieldType> &column_polynomials,
                        std::shared_ptr<math::evaluation_domain<FieldType>> original_domain,
                        std::uint32_t max_gates_degree,
                        const polynomial_dfs_type &mask_polynomial,
                        const polynomial_dfs_type &lagrange_0,
                        transcript_type& transcript
                    ) {
                        PROFILE_SCOPE("gate_argument_time");

                        // max_gates_degree that comes from the outside does not take into account multiplication
                        // by selector.
                        ++max_gates_degree;
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        auto value_type_to_polynomial_dfs = [](
                            const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };

                        std::vector<std::uint32_t> extended_domain_sizes;
                        std::vector<std::uint32_t> degree_limits;
                        std::uint32_t max_degree = std::pow(2, ceil(std::log2(max_gates_degree)));
                        std::uint32_t max_domain_size = original_domain->m * max_degree;

                        degree_limits.push_back(max_degree);
                        extended_domain_sizes.push_back(max_domain_size);
                        degree_limits.push_back(max_degree / 2);
                        extended_domain_sizes.push_back(max_domain_size / 2);

                        std::vector<math::expression<variable_type>> expressions(extended_domain_sizes.size());
                        auto theta_acc = FieldType::value_type::one();

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        math::expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);

                        math::expression_max_degree_visitor<variable_type> visitor;

                        const auto& gates = constraint_system.gates();

                        for (const auto& gate: gates) {
                            std::vector<math::expression<variable_type>> gate_results(extended_domain_sizes.size());
                            for (std::size_t constraint_idx = 0; constraint_idx < gate.constraints.size(); ++constraint_idx) {
                                const auto& constraint = gate.constraints[constraint_idx];
                                auto next_term = constraint * theta_acc;

                                theta_acc *= theta;
                                // +1 stands for the selector multiplication.
                                size_t constraint_degree = visitor.compute_max_degree(constraint) + 1;
                                for (int i = extended_domain_sizes.size() - 1; i >= 0; --i) {
                                    // Whatever the degree of term is, add it to the maximal degree expression.
                                    if (degree_limits[i] >= constraint_degree || i == 0) {
                                        gate_results[i] += next_term;
                                        break;
                                    }
                                }
                            }
                            variable_type selector(gate.selector_index, 0, false, variable_type::column_type::selector);
                            for (size_t i = 0; i < extended_domain_sizes.size(); ++i) {
                                gate_results[i] *= selector;
                                expressions[i] += gate_results[i];
                            }
                        }
                        std::array<polynomial_dfs_type, argument_size> F;

                        F[0] = polynomial_dfs_type::zero();
                        for (std::size_t i = 0; i < extended_domain_sizes.size(); ++i) {
                            std::unordered_map<variable_type, polynomial_dfs_type> variable_values;

                            build_variable_value_map(
                                expressions[i], column_polynomials, original_domain,
                                extended_domain_sizes[i], variable_values,
                                mask_polynomial, lagrange_0
                            );

                            polynomial_dfs_type result(extended_domain_sizes[i] - 1, extended_domain_sizes[i]);
                            wait_for_all(parallel_run_in_chunks<void>(
                                extended_domain_sizes[i],
                                [&variable_values, &extended_domain_sizes, &result, &expressions, i]
                                (std::size_t begin, std::size_t end) {
                                    for (std::size_t j = begin; j < end; ++j) {
                                        // Don't use cache here. In practice it's slower to maintain the cache
                                        // than to re-compute the subexpression value when value type is field element.
                                        math::expression_evaluator<variable_type> evaluator(
                                            expressions[i],
                                            [&assignments=variable_values, j]
                                                (const variable_type &var) -> const typename FieldType::value_type& {
                                                    return assignments[var][j];
                                            });
                                        result[j] = evaluator.evaluate();
                                    }
                            }, ThreadPool::PoolLevel::HIGH));

                            F[0] += result;
                        };
                        return F;
                    }
#else
                    static inline std::unordered_map<variable_type, sycl::event> build_variable_value_map(
                        const math::expression<variable_type>& expr,
                        const plonk_polynomial_dfs_table<FieldType>& assignments,

                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                        std::shared_ptr<math::evaluation_domain<FieldType>> extended_domain,

                        std::shared_ptr<value_type> original_domain_buf,
                        std::shared_ptr<value_type> extended_domain_buf,

                        std::unordered_map<variable_type, std::shared_ptr<value_type>>& variable_values_out,
                        std::shared_ptr<value_type> mask_polynomial_buf,
                        std::shared_ptr<value_type> mask_lagrange_diff_buf,

                        sycl::queue& queue,
                        actor::core::sycl_garbage_collector<polynomial_dfs_type>& dfs_garbage_collector,
                        sycl::event mask_polynomial_event,
                        sycl::event mask_lagrange_diff_event,
                        sycl::event original_domain_event,
                        sycl::event extended_domain_event
                    ) {
                        using value_type = typename FieldType::value_type;

                        const std::size_t cur_domain_size = domain->m;
                        const std::size_t extended_domain_size = extended_domain->m;

                        std::unordered_map<variable_type, sycl::event> variable_copy_events;
                        std::unordered_map<variable_type, sycl::event> variable_events_map;

                        math::expression_for_each_variable_visitor<variable_type> visitor(
                            [&variable_values_out, &variable_copy_events, &queue, &extended_domain_size]
                             (const variable_type& var) {
                                // Create the structure of the map so we can change the values later.
                                if (variable_values_out.find(var) == variable_values_out.end()) {
                                    if (var.index != PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED &&
                                        var.index != PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED ||
                                        var.type != variable_type::column_type::selector
                                    ) [[likely]] {
                                        variable_values_out[var] =
                                            nil::actor::core::make_shared_device_memory<value_type>(
                                                extended_domain_size, queue);
                                    } else {
                                        variable_values_out[var] = nullptr;
                                    }
                                }
                        });

                        visitor.visit(expr);
                        for (auto& [var, assignment] : variable_values_out) {
                            // Convert the variable to polynomial_dfs variable type.
                            polynomial_dfs_variable_type var_dfs(var.index, var.rotation, var.relative,
                                static_cast<typename polynomial_dfs_variable_type::column_type>(
                                    static_cast<std::uint8_t>(var.type)));
                            if( var.index == PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED && var.type == variable_type::column_type::selector ) {
                                variable_values_out[var] = mask_polynomial_buf;
                                variable_events_map[var] = mask_polynomial_event;
                            } else if( var.index == PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED && var.type == variable_type::column_type::selector ) {
                                variable_values_out[var] = mask_lagrange_diff_buf;
                                variable_events_map[var] = mask_lagrange_diff_event;
                            } else [[likely]] {
                                // logic here confused me a lot, hence this comment
                                // if rotation == 0 we can just copy the value
                                // otherwise we need to shift the value, creating a new column in the process
                                // the new column has to be loaded in memory to ensure that the pointer is valid
                                if (var.rotation == 0) {
                                    sycl::event variable_copy_event = queue.copy<value_type>(
                                        assignments.get_variable_value_without_rotation(var_dfs).data(),
                                        assignment.get(), cur_domain_size
                                    );
                                    variable_events_map[var] = handle_polynomial_resizing<FieldType>(
                                        assignment.get(), cur_domain_size, extended_domain_size,
                                        assignments.get_variable_value(var_dfs, domain).degree(),
                                        original_domain_buf.get(), extended_domain_buf.get(),
                                        queue, variable_copy_event, original_domain_event, extended_domain_event
                                    );
                                } else {
                                    std::shared_ptr<polynomial_dfs_type> shifted_val =
                                        std::make_shared<polynomial_dfs_type>(assignments.get_variable_value(var_dfs, domain));
                                    sycl::event shifted_val_copy_event = queue.copy<value_type>(
                                        shifted_val->data(), assignment.get(), cur_domain_size
                                    );
                                    sycl::event resize_event = handle_polynomial_resizing<FieldType>(
                                        assignment.get(), cur_domain_size, extended_domain_size,
                                        shifted_val->degree(),
                                        original_domain_buf.get(), extended_domain_buf.get(),
                                        queue, shifted_val_copy_event, original_domain_event, extended_domain_event
                                    );
                                    dfs_garbage_collector.track_memory(shifted_val, resize_event);
                                    variable_events_map[var] = resize_event;
                                }
                            }
                        }
                        return variable_events_map;
                    }

                    static inline std::array<polynomial_dfs_type, argument_size> prove_eval(
                        const typename policy_type::constraint_system_type &constraint_system,
                        const plonk_polynomial_dfs_table<FieldType> &column_polynomials,
                        std::shared_ptr<math::evaluation_domain<FieldType>> original_domain,
                        std::uint32_t max_gates_degree,
                        const polynomial_dfs_type &mask_polynomial,
                        const polynomial_dfs_type &lagrange_0,
                        transcript_type& transcript
                    ) {
                        PROFILE_SCOPE("gate_argument_time");

                        sycl::queue queue;

                        const std::size_t original_domain_size = original_domain->m;
                        std::shared_ptr<value_type> original_domain_buf =
                            nil::actor::core::make_shared_device_memory<value_type>(original_domain_size, queue);
                        auto original_domain_event = queue.copy<value_type>(
                            original_domain->get_fft_cache()->second.data(), original_domain_buf.get(), original_domain_size
                        );

                        // max_gates_degree that comes from the outside does not take into account multiplication
                        // by selector.
                        ++max_gates_degree;
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::vector<std::uint32_t> extended_domain_sizes;
                        std::vector<std::uint32_t> degree_limits;
                        std::uint32_t max_degree = std::pow(2, ceil(std::log2(max_gates_degree)));
                        std::uint32_t max_domain_size = original_domain_size * max_degree;

                        degree_limits.push_back(max_degree);
                        extended_domain_sizes.push_back(max_domain_size);
                        degree_limits.push_back(max_degree / 2);
                        extended_domain_sizes.push_back(max_domain_size / 2);

                        const std::size_t extended_domain_amount = extended_domain_sizes.size();

                        std::vector<math::expression<variable_type>> expressions(extended_domain_amount);
                        auto theta_acc = FieldType::value_type::one();

                        const auto& gates = constraint_system.gates();

                        math::expression_max_degree_visitor<variable_type> visitor;

                        actor::core::sycl_garbage_collector<value_type> garbage_collector(queue);
                        actor::core::sycl_garbage_collector<polynomial_dfs_type> dfs_garbage_collector(queue);

                        for (const auto& gate: gates) {
                            std::vector<math::expression<variable_type>> gate_results(extended_domain_amount);
                            for (std::size_t constraint_idx = 0; constraint_idx < gate.constraints.size(); ++constraint_idx) {
                                const auto& constraint = gate.constraints[constraint_idx];
                                auto next_term = constraint * theta_acc;

                                theta_acc *= theta;
                                // +1 stands for the selector multiplication.
                                size_t constraint_degree = visitor.compute_max_degree(constraint) + 1;
                                for (int i = extended_domain_amount - 1; i >= 0; --i) {
                                    // Whatever the degree of term is, add it to the maximal degree expression.
                                    if (degree_limits[i] >= constraint_degree || i == 0) {
                                        gate_results[i] += next_term;
                                        break;
                                    }
                                }
                            }
                            variable_type selector(gate.selector_index, 0, false, variable_type::column_type::selector);
                            for (size_t i = 0; i < extended_domain_amount; ++i) {
                                gate_results[i] *= selector;
                                expressions[i] += gate_results[i];
                            }
                        }

                        std::vector<std::unordered_map<variable_type, std::shared_ptr<value_type>>>
                            variable_values(extended_domain_amount);
                        std::vector<std::shared_ptr<value_type>> mask_polynomial_bufs(extended_domain_amount);
                        std::vector<std::shared_ptr<value_type>> mask_lagrange_diff_bufs(extended_domain_amount);
                        std::vector<std::shared_ptr<value_type>> lagrange_0_bufs(extended_domain_amount);

                        std::vector<std::shared_ptr<value_type>> result_bufs(extended_domain_amount);
                        std::vector<sycl::event> result_events(extended_domain_amount);

                        std::vector<std::shared_ptr<value_type>> extended_domain_bufs_first(extended_domain_amount),
                                                                 extended_domain_bufs_second(extended_domain_amount);
                        std::vector<sycl::event> extended_domain_events_first(extended_domain_amount),
                                                 extended_domain_events_second(extended_domain_amount);
                        std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>>
                            extended_domains(extended_domain_amount);
                        for (std::size_t i = 0; i < extended_domain_amount; ++i) {
                            extended_domain_bufs_first[i] =
                                nil::actor::core::make_shared_device_memory<value_type>(extended_domain_sizes[i], queue);
                            extended_domains[i] = math::make_evaluation_domain<FieldType>(extended_domain_sizes[i]);
                            extended_domain_events_first[i] = queue.copy<value_type>(
                                extended_domains[i]->get_fft_cache()->first.data(), extended_domain_bufs_first[i].get(), extended_domain_sizes[i]
                            );
                            // note that we never actually have to resize from max domain, so we do not
                            // move the buffer to the gpu
                            if (i != 0) {
                                extended_domain_bufs_second[i] =
                                    nil::actor::core::make_shared_device_memory<value_type>(extended_domain_sizes[i], queue);
                                extended_domain_events_second[i] = queue.copy<value_type>(
                                    extended_domains[i]->get_fft_cache()->second.data(), extended_domain_bufs_second[i].get(), extended_domain_sizes[i]
                                );
                            }
                        }

                        std::vector<gpu_expression_evaluator<variable_type>> evaluators;
                        for (std::size_t i = 0; i < extended_domain_amount; ++i) {
                            const std::size_t extended_domain_size = extended_domain_sizes[i];

                            std::shared_ptr<value_type> mask_polynomial_buf = mask_polynomial_bufs[i] =
                                nil::actor::core::make_shared_device_memory<value_type>(extended_domain_size, queue);
                            std::shared_ptr<value_type> lagrange_0_buf = lagrange_0_bufs[i] =
                                nil::actor::core::make_shared_device_memory<value_type>(extended_domain_size, queue);
                            std::shared_ptr<value_type> mask_lagrange_diff_buf = mask_lagrange_diff_bufs[i] =
                                nil::actor::core::make_shared_device_memory<value_type>(extended_domain_size, queue);
                            value_type* mask_polynomial_buf_ptr = mask_polynomial_buf.get();
                            value_type* lagrange_0_buf_ptr = lagrange_0_buf.get();
                            value_type* mask_lagrange_diff_buf_ptr = mask_lagrange_diff_buf.get();

                            sycl::event mask_polynomial_copy_event = queue.copy<value_type>(
                                mask_polynomial.data(), mask_polynomial_buf_ptr, mask_polynomial.size()
                            );
                            sycl::event mask_polynomial_resize_event = handle_polynomial_resizing<FieldType>(
                                mask_polynomial_buf_ptr, original_domain_size, extended_domain_size, mask_polynomial.degree(),
                                original_domain_buf.get(), extended_domain_bufs_first[i].get(),
                                queue, mask_polynomial_copy_event, original_domain_event, extended_domain_events_first[i]
                            );

                            sycl::event lagrange_0_copy_event = queue.copy<value_type>(
                                lagrange_0.data(), lagrange_0_buf.get(), lagrange_0.size()
                            );
                            sycl::event lagrange_0_resize_event = handle_polynomial_resizing<FieldType>(
                                lagrange_0_buf.get(), original_domain_size, extended_domain_size, lagrange_0.degree(),
                                original_domain_buf.get(), extended_domain_bufs_first[i].get(),
                                queue, lagrange_0_copy_event, original_domain_event, extended_domain_events_first[i]
                            );

                            sycl::event mask_lagrange_diff_event = queue.submit(
                                [mask_lagrange_diff_buf_ptr, mask_polynomial_buf_ptr, lagrange_0_buf_ptr, extended_domain_size,
                                 mask_polynomial_resize_event, lagrange_0_resize_event](sycl::handler& cgh) {
                                    cgh.depends_on({mask_polynomial_resize_event, lagrange_0_resize_event});
                                    cgh.parallel_for(sycl::range<1>(extended_domain_size), [=](sycl::id<1> idx) {
                                        mask_lagrange_diff_buf_ptr[idx] = mask_polynomial_buf_ptr[idx] - lagrange_0_buf_ptr[idx];
                                    });
                                });

                            auto variable_events_map = build_variable_value_map(
                                expressions[i], column_polynomials,
                                original_domain, extended_domains[i],
                                original_domain_buf, extended_domain_bufs_first[i],
                                variable_values[i], mask_polynomial_buf, mask_lagrange_diff_buf,
                                queue, dfs_garbage_collector, mask_polynomial_resize_event, lagrange_0_resize_event,
                                original_domain_event, extended_domain_events_first[i]
                            );
                            queue.wait();

                            evaluators.push_back(gpu_expression_evaluator<variable_type>(
                                queue, extended_domain_size, variable_values[i], variable_events_map, garbage_collector
                            ));

                            auto result_pair = evaluators[i](expressions[i]);
                            result_events[i] = result_pair.first;
                            result_bufs[i] = result_pair.second;
                            queue.wait();
                            // memory is tight, so we wait and delete unused stuff
                            // if we delete the waiting above, we should not clear memory here
                            // but stuff is not getting freed for some reason
                            mask_polynomial_bufs[i] = mask_polynomial_buf = nullptr;
                            lagrange_0_bufs[i] = lagrange_0_buf = nullptr;
                            dfs_garbage_collector.finalize_all();
                            garbage_collector.finalize_all();
                            variable_values[i].clear();
                            dfs_garbage_collector.clear();
                            garbage_collector.clear();
                        };
                        // resize all result buffers to max_domain_size
                        // note that for all but the max domain size we have to re-malloc the buffers
                        // due to the way handle_polynomial_resizing is implemented
                        std::vector<std::shared_ptr<value_type>> result_bufs_max(extended_domain_amount);
                        std::vector<sycl::event> result_bufs_max_events(extended_domain_amount);
                        result_bufs_max[0] = result_bufs[0];
                        result_bufs_max_events[0] = result_events[0];
                        // first domain is of max_domain_size, so we skip it
                        for (std::size_t i = 1; i < extended_domain_amount; ++i) {
                            result_bufs_max[i] =
                                nil::actor::core::make_shared_device_memory<value_type>(max_domain_size, queue);
                            result_bufs_max_events[i] = queue.copy<value_type>(
                                result_bufs[i].get(), result_bufs_max[i].get(), extended_domain_sizes[i], result_events[i]
                            );
                        }

                        std::vector<sycl::event> result_resize_events(extended_domain_amount);
                        result_resize_events[0] = result_bufs_max_events[0];
                        for (std::size_t i = 1; i < extended_domain_amount; ++i) {
                            result_resize_events[i] = handle_polynomial_resizing<FieldType>(
                                result_bufs_max[i].get(), extended_domain_sizes[i], max_domain_size,
                                extended_domain_sizes[i] - 1,
                                extended_domain_bufs_second[i].get(), extended_domain_bufs_first[0].get(),
                                queue, result_bufs_max_events[i], extended_domain_events_second[i], extended_domain_events_first[0]
                            );
                        }

                        std::vector<sycl::event> result_sum_events(extended_domain_amount);
                        result_sum_events[0] = result_resize_events[0];
                        value_type* F_buf = result_bufs_max[0].get();
                        for (std::size_t i = 1; i < extended_domain_amount; ++i) {
                            sycl::event prev_sum_event = result_sum_events[i - 1];
                            sycl::event resize_event = result_resize_events[i];
                            value_type* cur_summand_buf = result_bufs_max[i].get();
                            result_sum_events[i] =
                                queue.submit([F_buf, cur_summand_buf, prev_sum_event, resize_event, max_domain_size](sycl::handler& cgh) {
                                    cgh.depends_on({prev_sum_event, resize_event});
                                    cgh.parallel_for(sycl::range<1>(max_domain_size), [=](sycl::id<1> idx) {
                                        F_buf[idx] += cur_summand_buf[idx];
                                    });
                                });
                        }

                        std::array<polynomial_dfs_type, argument_size> F;
                        F[0] = polynomial_dfs_type(max_domain_size - 1, max_domain_size);
                        sycl::event f_copy_event = queue.copy<value_type>(
                            result_bufs_max[0].get(), F[0].data(), max_domain_size, result_sum_events.back()
                        );
                        f_copy_event.wait();

                        return F;
                    }
#endif
                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> &gates,
                                    typename policy_type::evaluation_map &evaluations,
                                    const typename FieldType::value_type &challenge,
                                    typename FieldType::value_type mask_value,
                                    transcript_type &transcript) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (const auto& gate: gates) {
                            typename FieldType::value_type gate_result = FieldType::value_type::zero();

                            for (const auto& constraint : gate.constraints) {
                                gate_result += constraint.evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int, typename plonk_variable<typename FieldType::value_type>::column_type> selector_key =
                                std::make_tuple(gate.selector_index, 0,
                                                plonk_variable<typename FieldType::value_type>::column_type::selector);

                            gate_result *= evaluations[selector_key];

                            F[0] += gate_result;
                        }

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
