//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
#define PARALLEL_CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP

#ifdef CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <unordered_map>
#include <queue>
#include <thread>
#include <format>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/polynomial/static_simd_vector.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/centralized_expression_evaluator.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

#include <nil/crypto3/zk/math/dag_expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename CommitmentSchemeTypePermutation, typename ParamsType>
                class placeholder_lookup_argument_prover {
                    using value_type = typename FieldType::value_type;

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
                    using variable_type = plonk_variable<value_type>;
                    using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;
                    using commitment_scheme_type = CommitmentSchemeTypePermutation;
                    using expression_type = expression<polynomial_dfs_variable_type>;
                    using central_evaluator_type = CentralAssignmentTableExpressionEvaluator<FieldType>;

                    static constexpr std::size_t argument_size = 4;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                public:

                    struct prover_lookup_result {
                        std::array<polynomial_dfs_type, argument_size> F_dfs;
                        typename commitment_scheme_type::commitment_type lookup_commitment;
                    };

                    placeholder_lookup_argument_prover(
                            const plonk_constraint_system<FieldType> &constraint_system,
                            const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type
                                &preprocessed_data,
                            central_evaluator_type& central_expr_evaluator,
                            const plonk_polynomial_dfs_table<FieldType>& plonk_columns,
                            commitment_scheme_type &commitment_scheme,
                            transcript_type &transcript)
                        : constraint_system(constraint_system)
                        , preprocessed_data(preprocessed_data)
                        , _central_expr_evaluator(central_expr_evaluator)
                        , plonk_columns(plonk_columns)
                        , commitment_scheme(commitment_scheme)
                        , transcript(transcript)
                        , basic_domain(preprocessed_data.common_data->basic_domain)
                        , lookup_gates(constraint_system.lookup_gates())
                        , lookup_tables(constraint_system.lookup_tables())
                        , lookup_chunks(0)
                        , usable_rows_amount(preprocessed_data.common_data->desc.usable_rows_amount)
                    {
                        // $/theta = \challenge$
                        theta = transcript.template challenge<FieldType>();
                    }

                    prover_lookup_result prove_eval() {
                        PROFILE_SCOPE("Lookup argument prove eval");

                        const auto& assignment_desc = preprocessed_data.common_data->desc;

                        value_type one = FieldType::value_type::one();

                        polynomial_dfs_type one_polynomial(0, basic_domain->m, one);

                        // We wanted to collect all the expressions and evaluate them at once, but usage of transcript does not allow that.
                        // So we are computing the required values for each prover step separately.
                        _central_expr_evaluator.register_expressions(this->get_lookup_input_expressions());
                        auto [lookup_value_expressions, lookup_tags] = this->get_lookup_value_expressions();
                        _central_expr_evaluator.register_expressions(lookup_value_expressions);
                        // We use these lookup tags in double sized evaluation domain.
                        _central_expr_evaluator.ensure_cache(lookup_tags, _central_expr_evaluator.get_original_domain_size() * 2);
                        _central_expr_evaluator.evaluate_all();

                        std::unique_ptr<std::vector<polynomial_dfs_type>> lookup_value_ptr =
                            get_lookup_values();
                        auto& lookup_value = *lookup_value_ptr;

                        std::unique_ptr<std::vector<polynomial_dfs_type>> lookup_input_ptr = get_lookup_input();
                        auto& lookup_input = *lookup_input_ptr;

                        // Lookup_input and lookup_value are ready
                        // Reduce value and input, count how many times lookup inputs appear in lookup values.
                        auto reduced_value_ptr = std::make_unique<std::vector<polynomial_dfs_type>>();
                        auto& reduced_value = *reduced_value_ptr;

                        for (std::size_t i = 0; i < lookup_value.size(); i++) {
                            reduced_value.push_back(reduce_dfs_polynomial_domain(lookup_value[i], basic_domain->m));
                        }
                        auto reduced_input_ptr = std::make_unique<std::vector<polynomial_dfs_type>>();
                        auto& reduced_input = *reduced_input_ptr;

                        reduced_input.resize(lookup_input.size(), polynomial_dfs_type::zero());

                        parallel_for(0, lookup_input.size(),
                            [&reduced_input, &lookup_input, this](std::size_t i) {
                                reduced_input[i] = reduce_dfs_polynomial_domain(lookup_input[i], this->basic_domain->m);
                            }, ThreadPool::PoolLevel::HIGH);

                        // Compute the counts of how many times a lookup input appears in the lookup values.
                        std::vector<polynomial_dfs_type> counts = count_lookup_input_appearances(
                            reduced_input, reduced_value, basic_domain->m, usable_rows_amount);

                        // Commit to the counts.
                        commitment_scheme.append_to_batch(LOOKUP_BATCH, counts);

                        typename commitment_scheme_type::commitment_type lookup_commitment = commitment_scheme.commit(LOOKUP_BATCH);
                        transcript(lookup_commitment);

                        value_type alpha = transcript.template challenge<FieldType>();

                        std::vector<polynomial_dfs_type> hs = compute_h_polys(reduced_input, alpha);
                        std::vector<polynomial_dfs_type> gs = compute_g_polys(reduced_value, counts, alpha);

                        // We don't use reduced_input and reduced_value after this line.
                        reduced_input_ptr.reset(nullptr);
                        reduced_value_ptr.reset(nullptr);

                        PROFILE_SCOPE("Lookup argument work on h and g");

                        // Compute polynomial U: U(wX) - U(X) = Sum(hs) + Sum(gs).
                        polynomial_dfs_type sum_H_G = polynomial_sum<FieldType>(hs) + polynomial_sum<FieldType>(gs);
                        polynomial_dfs_type U(basic_domain->m - 1, basic_domain->m, FieldType::value_type::zero());

                        U[0] = FieldType::value_type::zero();
                        for (std::size_t i = 1; i <= usable_rows_amount; i++) {
                            U[i] = U[i - 1];
                            U[i] += sum_H_G[i - 1];
                        }

                        // Commit to hs, gs and U.
                        commitment_scheme.append_to_batch(PERMUTATION_BATCH, U);
                        commitment_scheme.append_to_batch(PERMUTATION_BATCH, hs);
                        commitment_scheme.append_to_batch(PERMUTATION_BATCH, gs);

                        // TODO(martun): Make sure we don't need to commit to permutation batch here, we are committing to it
                        // in prover.hpp after lookup argument is ran.
                        std::array<polynomial_dfs_type, argument_size> F_dfs;

                        // Create a constraint for H_i(X) * (alpha - F_i(X)) + 1 == 0.
                        value_type h_challenge = transcript.template challenge<FieldType>();
                        std::vector<value_type> h_challenges;
                        h_challenges.push_back(h_challenge);
                        for (size_t i = 1; i < hs.size(); ++i) {
                            h_challenges.push_back(h_challenges.back() * h_challenge);
                        }

                        std::vector<polynomial_dfs_type> h_constraint_parts(hs.size());
                        {
                            PROFILE_SCOPE(
                                "Lookup argument compute h constraint parts of size {}",
                                hs.size());

                            // Resize each of hs 2x the size of the corresponding lookup_input.
                            // This will later change to a batch resize.
                            parallel_for(
                                0, hs.size(),
                                [&hs, &h_constraint_parts, &lookup_input](std::size_t i) {
                                    hs[i].resize(lookup_input[i].size() * 2);
                                },
                                ThreadPool::PoolLevel::HIGH);
                            parallel_for(
                                0, hs.size(),
                                [&hs, &h_constraint_parts, &lookup_input](std::size_t i) {
                                    lookup_input[i].resize(lookup_input[i].size() * 2);
                                },
                                ThreadPool::PoolLevel::HIGH);

                            parallel_for(
                                0, hs.size(),
                                [&hs, &h_constraint_parts, &h_challenges, &alpha,
                                 &lookup_input, &one](std::size_t i) {
                                    h_constraint_parts[i] = -lookup_input[i];
                                    h_constraint_parts[i] += alpha;
                                    h_constraint_parts[i] *= hs[i];
                                    h_constraint_parts[i] += one;
                                    h_constraint_parts[i] *= h_challenges[i];
                                },
                                ThreadPool::PoolLevel::HIGH);
                        }

                        F_dfs[0] = polynomial_sum<FieldType>(std::move(h_constraint_parts));

                        // Create a constraint for G_i(X) * (alpha - t_i(X)) - m_i(X) == 0.
                        value_type g_challenge = transcript.template challenge<FieldType>();
                        std::vector<value_type> g_challenges;
                        g_challenges.push_back(g_challenge);
                        for (size_t i = 1; i < gs.size(); ++i) {
                            g_challenges.push_back(g_challenges.back() * g_challenge);
                        }

                        std::vector<polynomial_dfs_type> g_constraint_parts(gs.size());

                        {
                            PROFILE_SCOPE(
                                "Lookup argument compute g constraint parts of size {}",
                                gs.size());
                            parallel_for(
                                0, gs.size(),
                                [&gs, &g_constraint_parts, &g_challenges, &alpha,
                                 &lookup_value, &counts](std::size_t i) {
                                    g_constraint_parts[i] =
                                        g_challenges[i] *
                                        (gs[i] * (alpha - lookup_value[i]) - counts[i]);
                                },
                                ThreadPool::PoolLevel::HIGH);
                        }

                        {
                            PROFILE_SCOPE("Lookup argument compute F_dfs[0]");
                            F_dfs[0] +=
                                polynomial_sum<FieldType>(std::move(g_constraint_parts));
                        }

                        {
                            PROFILE_SCOPE("Lookup argument compute F_dfs[1]");
                            // Check that U[0] == 0.
                            F_dfs[1] = preprocessed_data.common_data->lagrange_0 * U;
                        }

                        {
                            PROFILE_SCOPE("Lookup argument compute F_dfs[2]");
                            // Check that U[Nu] == 0.
                            F_dfs[2] = preprocessed_data.q_last * U;
                        }

                        {
                            PROFILE_SCOPE("Lookup argument compute F_dfs[3]");
                            // Check that Mask(X) * (U(wX) - U(X) - Sum(hs) - Sum(gs)) ==
                            // 0.
                            F_dfs[3] = math::polynomial_shift(U, 1, basic_domain->m) - U -
                                       sum_H_G;
                            F_dfs[3] *=
                                (preprocessed_data.q_last + preprocessed_data.q_blind) -
                                one_polynomial;
                        }

                        return {
                            std::move(F_dfs),
                            std::move(lookup_commitment)
                        };
                    }
                private:
                    // Computes the helper polynomials H_i(X) = -1 / (alpha - c_i(X)) over the domain.
                    std::vector<polynomial_dfs_type> compute_h_polys(
                            const std::vector<polynomial_dfs_type>& lookup_input,
                            const value_type& alpha) {
                        PROFILE_SCOPE("Lookup argument computing polynomials H_i");

                        std::vector<polynomial_dfs_type> Hs = lookup_input;
                        parallel_for(0, Hs.size(), [&Hs, &alpha](std::size_t i) {
                             Hs[i] -= alpha;
                             Hs[i].element_wise_inverse();
                        }, ThreadPool::PoolLevel::HIGH);

                        return Hs;
                    }

                    // Computes the helper polynomials G_i(X) = m_i(X) / (alpha - t_i(X)) over the domain.
                    std::vector<polynomial_dfs_type> compute_g_polys(
                            const std::vector<polynomial_dfs_type>& lookup_value,
                            const std::vector<polynomial_dfs_type>& counts,
                            const value_type& alpha) {
                        PROFILE_SCOPE("Lookup argument computing polynomials G_i");

                        std::vector<polynomial_dfs_type> Gs = lookup_value;
                        parallel_for(0, Gs.size(), [&Gs, &alpha, &counts](std::size_t i) {
                            auto& g = Gs[i];
                            for (size_t j = 0; j < g.size(); ++j) {
                                g[j] = alpha - g[j];
                            }
                            g.element_wise_inverse();

                            // Don't multiply as polynomials here, they will resize.
                            for (size_t j = 0; j < g.size(); ++j) {
                                g[j] *= counts[i][j];
                            }
                        }, ThreadPool::PoolLevel::HIGH);
                        return Gs;
                    }

                    /** Returns all the expressions that are required for lookup value computation.
                     */
                    std::pair<std::vector<expression_type>, std::set<polynomial_dfs_variable_type>> get_lookup_value_expressions() {
                        PROFILE_SCOPE("Lookup argument preparing lookup value expressions");

                        std::vector<expression_type> expressions;
                        std::set<polynomial_dfs_variable_type> lookup_tags;

                        for (std::size_t t_id = 0; t_id < lookup_tables.size(); t_id++) {
                            const plonk_lookup_table<FieldType> &l_table = lookup_tables[t_id];

                            polynomial_dfs_variable_type lookup_tag(
                                        l_table.tag_index, 0, false,
                                        polynomial_dfs_variable_type::column_type::selector);

                            lookup_tags.insert(lookup_tag);
                            for (size_t o_id = 0; o_id < l_table.lookup_options.size(); ++o_id) {
                                for (std::size_t i = 0; i < l_table.columns_number; i++) {
                                    expressions.push_back(lookup_tag * l_table.lookup_options[o_id][i]);
                                }
                            }
                        }
                        return {expressions, lookup_tags};
                    }

                    std::unique_ptr<std::vector<polynomial_dfs_type>> get_lookup_values() {
                        PROFILE_SCOPE("Lookup argument preparing lookup value");

                        auto lookup_value_ptr = std::make_unique<std::vector<polynomial_dfs_type>>();
                        for (std::size_t t_id = 0; t_id < lookup_tables.size(); t_id++) {
                            const plonk_lookup_table<FieldType> &l_table = lookup_tables[t_id];
                            polynomial_dfs_variable_type lookup_tag_selector(
                                l_table.tag_index, 0, false,
                                polynomial_dfs_variable_type::column_type::selector);

                            // Get the selector value in double size, since computations below
                            // will resize everything to double size.
                            std::shared_ptr<polynomial_dfs_type> lookup_tag = _central_expr_evaluator.get(
                                lookup_tag_selector,  _central_expr_evaluator.get_original_domain_size() * 2);
                            
                            // Increase the size to fit the next table values.
                            std::size_t lookup_values_used = lookup_value_ptr->size();
                            lookup_value_ptr->resize(lookup_values_used + l_table.lookup_options.size());

                            parallel_for(0, l_table.lookup_options.size(),
                                [&l_table, t_id, &lookup_tag, &lookup_tag_selector, this, &lookup_value_ptr, lookup_values_used]
                                (std::size_t o_id) {
                                    polynomial_dfs_type v = (value_type(t_id + 1)) * (*lookup_tag);
                                    value_type theta_acc = this->theta;
                                    for (std::size_t i = 0; i < l_table.columns_number; i++) {
                                        v += theta_acc * this->_central_expr_evaluator.get_expression_value(
                                            lookup_tag_selector * l_table.lookup_options[o_id][i]);
                                        theta_acc *= this->theta;
                                    }
                                    (*lookup_value_ptr)[lookup_values_used + o_id] = v;
                                }, ThreadPool::PoolLevel::HIGH);
                        }
                        return std::move(lookup_value_ptr);
                    }

                    /** Returns all the expressions that are required for lookup inputs.
                     *  We don't use theta here, multiplication by theta powers will be done separately.
                     */
                    std::vector<expression_type> get_lookup_input_expressions() {
                        PROFILE_SCOPE("Lookup argument preparing lookup input expressions");

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        auto value_type_to_polynomial_dfs = [](
                            const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };
                        expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);
 
                        std::vector<expression_type> expressions;

                        for (const auto &gate : lookup_gates) {
                            // Build all expressions
                            for (const auto& constraint : gate.constraints) {
                                expression_type l = value_type_to_polynomial_dfs(constraint.table_id);
                                value_type theta_acc = this->theta;
                                for (const auto& expr : constraint.lookup_input) {
                                    l += converter.convert(theta_acc * expr);
                                    theta_acc *= this->theta;
                                }
                                if (gate.tag_index != PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                                    l *= polynomial_dfs_variable_type(
                                        gate.tag_index, 0, false,
                                        polynomial_dfs_variable_type::column_type::selector);
                                }

                                expressions.push_back(std::move(l));
                            }
                        }
                        return expressions;
                    }

                    std::unique_ptr<std::vector<polynomial_dfs_type>> get_lookup_input() {
                        PROFILE_SCOPE("Lookup argument preparing lookup input");

                        std::vector<expression_type> exprs = get_lookup_input_expressions();
                        
                        auto lookup_input_ptr = std::make_unique<std::vector<polynomial_dfs_type>>();
                        lookup_input_ptr->reserve(exprs.size());
                        for (const auto& expr: exprs) {
                            lookup_input_ptr->push_back(_central_expr_evaluator.get_expression_value(expr));
                        }
                        return lookup_input_ptr;
                    }

                    polynomial_dfs_type reduce_dfs_polynomial_domain(
                        const polynomial_dfs_type &polynomial,
                        const std::size_t &new_domain_size
                    ) {
                        BOOST_ASSERT(polynomial.size() % new_domain_size == 0);

                        if (polynomial.size() == new_domain_size)
                            return polynomial;

                        polynomial_dfs_type reduced(
                            new_domain_size - 1, new_domain_size, FieldType::value_type::zero());

                        std::size_t step = polynomial.size() / new_domain_size;
                        for (std::size_t i = 0; i < new_domain_size; i++) {
                            reduced[i] = polynomial[i * step];
                        }

                        return reduced;
                    }

                    // Counts how many times each values in 'reduced_value' appears in any 'reduced_input'.
                    // Returns a vector of polynomials, but inside are integers which are normally
                    // significantly smaller than the field size.
                    std::vector<polynomial_dfs_type> count_lookup_input_appearances(
                        const std::vector<polynomial_dfs_type>& reduced_input,
                        const std::vector<polynomial_dfs_type>& reduced_value,
                        std::size_t domain_size,
                        std::size_t usable_rows_amount
                    ) {
                        PROFILE_SCOPE("Count lookup input counts in lookup tables");

                        std::unordered_map<value_type, std::size_t> counts_map;
                        for (std::size_t i = 0; i < reduced_input.size(); i++) {
                            for (std::size_t j = 0; j < usable_rows_amount; j++) {
                                counts_map[reduced_input[i][j]]++;
                            }
                        }

                        std::vector<polynomial_dfs_type> result;
                        for (std::size_t i = 0; i < reduced_value.size(); i++) {
                            result.push_back(polynomial_dfs_type(domain_size - 1, domain_size));
                            for (std::size_t j = 0; j < usable_rows_amount; j++) {
                                result[i][j] = counts_map[reduced_value[i][j]];
                                // If the value repeats, we will not repeat the count.
                                counts_map[reduced_value[i][j]] = 0;
                            }
                        }
                        return result;
                    }

                    central_evaluator_type& _central_expr_evaluator;
                    const plonk_constraint_system<FieldType> &constraint_system;
                    const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type& preprocessed_data;
                    const plonk_polynomial_dfs_table<FieldType>& plonk_columns;
                    commitment_scheme_type& commitment_scheme;
                    transcript_type& transcript;
                    std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;
                    const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>>& lookup_gates;
                    const std::vector<plonk_lookup_table<FieldType>>& lookup_tables;
                    value_type theta;
                    std::size_t lookup_chunks;
                    const size_t usable_rows_amount;
                };

                template<typename FieldType, typename CommitmentSchemeTypePermutation, typename ParamsType>
                class placeholder_lookup_argument_verifier {
                    using value_type = typename FieldType::value_type;

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<value_type>;
                    using variable_type = plonk_variable<value_type>;
                    using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;
                    using commitment_scheme_type = CommitmentSchemeTypePermutation;


                    static constexpr std::size_t argument_size = 4;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                public:

                    void fill_challenge_queue(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type::common_data_type &common_data,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        // sorted_batch_values. Pair value/shifted_value
                        const std::vector<std::vector<value_type>> &sorted,
                        // Commitment
                        const typename CommitmentSchemeTypePermutation::commitment_type &lookup_commitment,
                        transcript_type &transcript,
                        std::queue<value_type>& queue
                    ) {
                        // Theta.
                        queue.push(transcript.template challenge<FieldType>());

                        transcript(lookup_commitment);

                        // alpha, h_challenge, g_challenge
                        queue.push(transcript.template challenge<FieldType>());
                        queue.push(transcript.template challenge<FieldType>());
                        queue.push(transcript.template challenge<FieldType>());
                    }

                    /**
                     * \param[in] challenge - The value of random challenge point 'Y'.
                     * \param[in] evaluations - A map containing evaluations of all the required variables and rotations, I.E. values of
                                                all the columns at points 'Y' and 'Y*omega' and other points depending on the rotations used.
                     * \param[in] counts - A vector containing the evaluation of polynomails "counts" at point 'T' for each lookup value.
                                           Each polynomial 'counts' shows the number of times each value appears in the lookup inputs.
                     * \returns A list of lookup argument values that are used as a part of the final zero-check pprotocol.
                     */
                    std::array<value_type, argument_size> verify_eval(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type::common_data_type &common_data,
                        const std::vector<value_type> &special_selector_values,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        const value_type &challenge,
                        typename policy_type::evaluation_map &evaluations,
                        const std::vector<value_type>& counts,
                        const value_type& U_value,
                        const value_type& U_shifted_value,
                        const std::vector<value_type>& hs,
                        const std::vector<value_type>& gs,
                        const typename CommitmentSchemeTypePermutation::commitment_type &lookup_commitment,
                        transcript_type &transcript = transcript_type()
                    ) {
                        const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> &lookup_gates =
                            constraint_system.lookup_gates();
                        const std::vector<plonk_lookup_table<FieldType>> &lookup_tables = constraint_system.lookup_tables();

                        std::array<value_type, argument_size> F;
                        // 1. Get theta
                        value_type theta = transcript.template challenge<FieldType>();

                        // 2. Add commitments to transcript
                        transcript(lookup_commitment);

                        // 3. Calculate lookup_value compression
                        value_type one = FieldType::value_type::one();

                        auto mask_value = (one - (special_selector_values[1] + special_selector_values[2]));

                        value_type theta_acc = one;
                        std::vector<value_type> lookup_value;
                        std::vector<value_type> shifted_lookup_value;
                        for (std::size_t t_id = 0; t_id < lookup_tables.size(); t_id++) {
                            const auto &table = lookup_tables[t_id];
                            auto key = std::tuple(table.tag_index, 0, plonk_variable<value_type>::column_type::selector);
                            auto shifted_key = std::tuple(table.tag_index, 1, plonk_variable<value_type>::column_type::selector);
                            value_type selector_value  = evaluations[key];
                            value_type shifted_selector_value  = evaluations[shifted_key];
                            for (std::size_t o_id = 0; o_id < table.lookup_options.size(); o_id++) {
                                value_type v = selector_value * (t_id + 1);
                                value_type shifted_v = shifted_selector_value * (t_id + 1);

                                theta_acc = theta;
                                BOOST_ASSERT(table.lookup_options[o_id].size() == table.columns_number);
                                for (std::size_t i = 0; i < table.lookup_options[o_id].size(); i++) {
                                    auto key1 = std::tuple(table.lookup_options[o_id][i].index, 0, table.lookup_options[o_id][i].type);
                                    auto shifted_key1 = std::tuple(table.lookup_options[o_id][i].index, 1, table.lookup_options[o_id][i].type);
                                    v += theta_acc * evaluations[key1] * selector_value;
                                    shifted_v += theta_acc * evaluations[shifted_key1]* shifted_selector_value;
                                    theta_acc *= theta;
                                }
                                lookup_value.push_back(v);
                                shifted_lookup_value.push_back(shifted_v);
                            }
                        }

                        // 4. Calculate compressed lookup inputs
                        std::vector<value_type> lookup_input;
                        for (std::size_t g_id = 0; g_id < lookup_gates.size(); g_id++) {
                            const auto &gate = lookup_gates[g_id];
                            auto key = std::tuple(gate.tag_index, 0, plonk_variable<value_type>::column_type::selector);
                            value_type selector_value = evaluations[key];
                            for (std::size_t c_id = 0; c_id < gate.constraints.size(); c_id++) {
                                const auto &constraint = gate.constraints[c_id];
                                value_type l = selector_value * constraint.table_id;
                                theta_acc = theta;
                                for (std::size_t k = 0; k < constraint.lookup_input.size(); k++) {
                                    l += selector_value * theta_acc * constraint.lookup_input[k].evaluate(evaluations);
                                    theta_acc *= theta;
                                }
                                lookup_input.push_back(l);
                            }
                        }

                        value_type alpha = transcript.template challenge<FieldType>();

                        value_type sum_H_G = std::accumulate(hs.begin(), hs.end(), FieldType::value_type::zero());
                        sum_H_G = std::accumulate(gs.begin(), gs.end(), sum_H_G);

                        value_type h_challenge = transcript.template challenge<FieldType>();
                        value_type h_challenge_acc = h_challenge;

                        F[0] = FieldType::value_type::zero();
                        for (size_t i = 0; i < hs.size(); ++i) {
                            F[0] += h_challenge_acc * (hs[i] * (alpha - lookup_input[i]) + one);
                            h_challenge_acc *= h_challenge;
                        }

                        // Create a constraint for G_i(X) * (alpha - t_i(X)) - m_i(X) == 0.
                        value_type g_challenge = transcript.template challenge<FieldType>();
                        value_type g_challenge_acc = g_challenge;

                        for (size_t i = 0; i < gs.size(); ++i) {
                            F[0] += g_challenge_acc * (gs[i] * (alpha - lookup_value[i]) - counts[i]);
                            g_challenge_acc *= g_challenge;
                        }

                        // Check that U[0] == 0.
                        F[1] = special_selector_values[0] * U_value;

                        // Check that U[Nu] == 0.
                        F[2] = special_selector_values[1] * U_value;

                        // Check that Mask(X) * (U(wX) - U(X) - Sum(hs) - Sum(gs)) == 0.
                        F[3] = U_shifted_value - U_value - sum_H_G;
                        F[3] *= (special_selector_values[1] + special_selector_values[2]) - one;

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
