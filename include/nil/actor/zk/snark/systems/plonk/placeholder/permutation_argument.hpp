//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef ACTOR_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP
#define ACTOR_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/actor/container/merkle/tree.hpp>

#include <nil/actor/math/polynomial/polynomial.hpp>
#include <nil/actor/math/polynomial/polynomial_dfs.hpp>
#include <nil/actor/math/polynomial/shift.hpp>

#include <nil/actor/zk/transcript/fiat_shamir.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

#include <nil/actor/core/smp.hh>
#include <nil/actor/core/when_all.hh>
#include <nil/actor/core/future.hh>

namespace nil {
    namespace actor {
        namespace zk {
            namespace snark {
                template<typename FieldType,
                         typename ParamsType>
                class placeholder_permutation_argument {

                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    static constexpr std::size_t argument_size = 3;

                    using permutation_commitment_scheme_type =
                        typename ParamsType::permutation_commitment_scheme_type;

                public:
                    struct prover_result_type {
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;

                        math::polynomial<typename FieldType::value_type> permutation_polynomial;

                        typename permutation_commitment_scheme_type::precommitment_type
                            permutation_poly_precommitment;
                    };

                    static inline future<prover_result_type> prove_eval(
                        plonk_constraint_system<FieldType,
                            typename ParamsType::arithmetization_params> &constraint_system,
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::
                                    preprocessed_data_type preprocessed_data,
                        const plonk_table_description<FieldType,
                                typename ParamsType::arithmetization_params> &table_description,
                        const plonk_polynomial_dfs_table<FieldType,
                            typename ParamsType::arithmetization_params> &column_polynomials,
                        typename ParamsType::commitment_params_type fri_params,
                        transcript_type &transcript = transcript_type()) {

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        auto last = std::chrono::high_resolution_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - last);
#endif
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_sigma =
                            preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_id =
                            preprocessed_data.identity_polynomials;
                        std::shared_ptr<crypto3::math::evaluation_domain<FieldType>> basic_domain = preprocessed_data.common_data.basic_domain;

                        // 1. $\beta_1, \gamma_1 = \challenge$
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();
                        // 2. Calculate id_binding, sigma_binding for j from 1 to N_rows
                        // 3. Calculate $V_P$
                        math::polynomial_dfs<typename FieldType::value_type> V_P(
                            basic_domain->size() - 1, basic_domain->size());
                        V_P[0] = FieldType::value_type::one();

                        std::vector<future<>> fut;
                        std::size_t cpu_usage = std::min(basic_domain->size(), (std::size_t)smp::count - 1);
                        std::size_t element_per_cpu = basic_domain->size() / (smp::count - 1);
                        std::cout << "Count=" << smp::count << std::endl;
                        std::vector<typename FieldType::value_type> V_P_coeff(basic_domain->size());
                        std::cout << "cpu_usage=" << cpu_usage << std::endl;
                        for (auto shard_id = cpu_usage; shard_id > 0; --shard_id) {
                            auto begin = (shard_id - 1 != 0) ? element_per_cpu * (shard_id  - 1) : 1;
                            auto end = (shard_id - 1 == cpu_usage - 1) ? basic_domain->size() : element_per_cpu * (shard_id - 1 + 1);
                            std::cout << "shard_id=" << shard_id - 1 << ' ' << begin << ' ' << end << std::endl;
                            fut.emplace_back(smp::submit_to(shard_id, [begin, end, beta, gamma, &basic_domain, &S_id, &S_sigma, &V_P_coeff, &column_polynomials]() {
                                for (std::size_t j = begin; j < end; ++j) {
                                    typename FieldType::value_type coeff = FieldType::value_type::one();
                                    for (std::size_t i = 0; i < S_id.size(); i++) {
                                        assert(column_polynomials[i].size() == basic_domain->size());
                                        assert(S_id[i].size() == basic_domain->size());
                                        assert(S_sigma[i].size() == basic_domain->size());

                                        coeff *= (column_polynomials[i][j - 1] + beta * S_id[i][j - 1] + gamma) /
                                                 (column_polynomials[i][j - 1] + beta * S_sigma[i][j - 1] + gamma);
                                    }
                                    V_P_coeff[j] = coeff;
                                    if (j % 100 == 0) {
                                        std::cout << "j=" << j << " shard=" << this_shard_id() << std::endl;
//                                        print("j=%d, core=%d", j, this_shard_id());
                                    }
                                }
                                return make_ready_future<>();
                            }));
                        }

                        fut[1].get();
                        fut[2].get();
                        fut[0].get();
                        for (std::size_t i = 1; i < V_P_coeff.size(); ++i) {
                            V_P[i] = V_P[i - 1] * V_P_coeff[i];
                        }

//                        for (std::size_t j = 1; j < basic_domain->size(); j++) {
//                            typename FieldType::value_type coeff = FieldType::value_type::one();
//
//                            for (std::size_t i = 0; i < S_id.size(); i++) {
//                                assert(column_polynomials[i].size() == basic_domain->size());
//                                assert(S_id[i].size() == basic_domain->size());
//                                assert(S_sigma[i].size() == basic_domain->size());
//
//                                coeff *= (column_polynomials[i][j - 1] + beta * S_id[i][j - 1] + gamma) /
//                                    (column_polynomials[i][j - 1] + beta * S_sigma[i][j - 1] + gamma);
//                            }
//                            V_P[j] = V_P[j - 1] * coeff;
//                        }
                        
                        V_P.resize(fri_params.D[0]->m).get();

                        math::polynomial<typename FieldType::value_type> V_P_normal =
                            math::polynomial<typename FieldType::value_type>(V_P.coefficients());
                        // 4. Compute and add commitment to $V_P$ to $\text{transcript}$.
                        typename permutation_commitment_scheme_type::precommitment_type V_P_tree =
                            algorithms::precommit<permutation_commitment_scheme_type>(V_P, fri_params.D[0]).get();
                        typename permutation_commitment_scheme_type::commitment_type V_P_commitment =
                            algorithms::commit<permutation_commitment_scheme_type>(V_P_tree);
                        transcript(V_P_commitment);
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - last);
                        std::cout << "4. Compute and add commitment to $V_P$ to $\\text{transcript}$.: " << std::fixed << std::setprecision(3) << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        // 5. Calculate g_perm, h_perm
                        math::polynomial_dfs<typename FieldType::value_type> g;
                        math::polynomial_dfs<typename FieldType::value_type> h;

                        for (std::size_t i = 0; i < S_id.size(); i++) {
                            if (i == 0) {
                                g = (column_polynomials[0] + beta * S_id[0] + gamma);
                                h = (column_polynomials[0] + beta * S_sigma[0] + gamma);
                            } else {
                                g = g * (column_polynomials[i] + beta * S_id[i] + gamma);
                                h = h * (column_polynomials[i] + beta * S_sigma[i] + gamma);
                            }
                        }

                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            0, V_P.size(), FieldType::value_type::one());
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;
                        math::polynomial_dfs<typename FieldType::value_type> V_P_shifted =
                            math::polynomial_shift(V_P, 1, basic_domain->m).get();

                        F[0] = math::polynomial<typename FieldType::value_type>(
                            (preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_P)).coefficients());
                        F[1] = math::polynomial<typename FieldType::value_type>(
                            ((one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                               (V_P_shifted * h - V_P * g)).coefficients());
                        F[2] = math::polynomial<typename FieldType::value_type>(
                            (preprocessed_data.q_last * (V_P * V_P - V_P)).coefficients());
                        prover_result_type res = {F, V_P_normal, V_P_tree};

                        return make_ready_future<prover_result_type>(res);
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const typename placeholder_public_preprocessor<FieldType, ParamsType>::
                                        preprocessed_data_type preprocessed_data,
                                    // y
                                    const typename FieldType::value_type &challenge,
                                    // f(y):
                                    const std::vector<typename FieldType::value_type> &column_polynomials_values,
                                    // V_P(y):
                                    const typename FieldType::value_type &perm_polynomial_value,
                                    // V_P(omega * y):
                                    const typename FieldType::value_type &perm_polynomial_shifted_value,
                                    const typename permutation_commitment_scheme_type::commitment_type &V_P_commitment,
                                    transcript_type &transcript = transcript_type()) {

                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_sigma =
                            preprocessed_data.permutation_polynomials;
                        const std::vector<math::polynomial_dfs<typename FieldType::value_type>> &S_id =
                            preprocessed_data.identity_polynomials;

                        // 1. Get beta, gamma
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        // 2. Add commitment to V_P to transcript
                        transcript(V_P_commitment);

                        // 3. Calculate h_perm, g_perm at challenge point
                        typename FieldType::value_type g = FieldType::value_type::one();
                        typename FieldType::value_type h = FieldType::value_type::one();

                        for (std::size_t i = 0; i < column_polynomials_values.size(); i++) {
                            g = g * (column_polynomials_values[i] + beta * S_id[i].evaluate(challenge) + gamma);
                            h = h * (column_polynomials_values[i] + beta * S_sigma[i].evaluate(challenge) + gamma);
                        }

                        std::array<typename FieldType::value_type, argument_size> F;
                        typename FieldType::value_type one = FieldType::value_type::one();

                        F[0] = preprocessed_data.common_data.lagrange_0.evaluate(challenge) * (one - perm_polynomial_value);
                        F[1] = (one - preprocessed_data.q_last.evaluate(challenge) -
                                preprocessed_data.q_blind.evaluate(challenge)) *
                               (perm_polynomial_shifted_value * h - perm_polynomial_value * g);
                        F[2] = preprocessed_data.q_last.evaluate(challenge) *
                               (perm_polynomial_value.squared() - perm_polynomial_value);

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace actor
}    // namespace nil

#endif    // #ifndef ACTOR_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP
