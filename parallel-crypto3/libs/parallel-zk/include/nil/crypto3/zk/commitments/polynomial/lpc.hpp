//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#define PARALLEL_CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

#include "nil/crypto3/math/polynomial/polymorphic_polynomial_dfs.hpp"
#ifdef CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <queue>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

#include <nil/actor/core/thread_pool.hpp>
#include <nil/actor/core/parallelization_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                // Placeholder-friendly class.
                // LPCScheme is usually 'batched_list_polynomial_commitment<...>'.
                template<typename LPCScheme, typename PolynomialType = typename math::polynomial_dfs<
                    typename LPCScheme::params_type::field_type::value_type>>
                class lpc_commitment_scheme : public polys_evaluator<typename LPCScheme::params_type,
                    typename LPCScheme::commitment_type, PolynomialType>{
                public:
                    static constexpr bool is_lpc(){return true;}

                    using field_type = typename LPCScheme::field_type;
                    using value_type = typename field_type::value_type;
                    using params_type = typename LPCScheme::params_type;
                    using precommitment_type = typename LPCScheme::precommitment_type;
                    using commitment_type = typename LPCScheme::commitment_type;
                    using fri_type = typename LPCScheme::fri_type;
                    using basic_fri = typename LPCScheme::fri_type;
                    using proof_type = typename LPCScheme::proof_type;
                    using aggregated_proof_type = typename LPCScheme::aggregated_proof_type;
                    using lpc_proof_type = typename LPCScheme::lpc_proof_type;
                    using fri_proof_type = typename LPCScheme::fri_proof_type;
                    using transcript_type = typename LPCScheme::transcript_type;
                    using transcript_hash_type = typename LPCScheme::transcript_hash_type;
                    using polynomial_type = PolynomialType;
                    using lpc = LPCScheme;
                    using eval_storage_type = typename LPCScheme::eval_storage_type;
                    using preprocessed_data_type = std::map<std::size_t, std::vector<value_type>>;
                    using polys_evaluator_type = polys_evaluator<typename LPCScheme::params_type,
                        typename LPCScheme::commitment_type, PolynomialType>;

                private:
                    std::map<std::size_t, precommitment_type> _trees;
                    typename fri_type::params_type _fri_params;
                    value_type _etha;
                    std::map<std::size_t, bool> _batch_fixed;
                    preprocessed_data_type _fixed_polys_values;

                public:
                    // Getters for the upper fields. Used from marshalling only so far.
                    const std::map<std::size_t, precommitment_type>& get_trees() const {return _trees;}
                    const typename fri_type::params_type& get_fri_params() const {return _fri_params;}
                    const value_type& get_etha() const {return _etha;}
                    const std::map<std::size_t, bool>& get_batch_fixed() const {return _batch_fixed;}
                    const preprocessed_data_type& get_fixed_polys_values() const {return _fixed_polys_values;}

                    // We must set it in verifier, taking this value from common data.
                    void set_fixed_polys_values(const preprocessed_data_type& value) {_fixed_polys_values = value;}

                    // This constructor is normally used from marshalling, to recover the LPC state from a file.
                    // Maybe we want the move variant of this constructor.
                    lpc_commitment_scheme(
                            const polys_evaluator_type& polys_evaluator,
                            const std::map<std::size_t, precommitment_type>& trees,
                            const typename fri_type::params_type& fri_params,
                            const value_type& etha,
                            const std::map<std::size_t, bool>& batch_fixed,
                            const preprocessed_data_type& fixed_polys_values)
                        : polys_evaluator_type(polys_evaluator)
                        , _trees(trees)
                        , _fri_params(fri_params)
                        , _etha(etha)
                        , _batch_fixed(batch_fixed)
                        , _fixed_polys_values(fixed_polys_values)
                    {
                    }


                    lpc_commitment_scheme(const typename fri_type::params_type &fri_params)
                        : _fri_params(fri_params), _etha(0u) {
                    }

                    preprocessed_data_type preprocess(transcript_type& transcript) const {
                        auto etha = transcript.template challenge<field_type>();

                        preprocessed_data_type result;
                        for(auto const&[index, fixed]: _batch_fixed) {
                            if (!fixed)
                                continue;
                            result[index] = {};
                            for (const auto& poly: this->_polys.at(index)){
                                result[index].push_back(poly.evaluate(etha));
                            }
                        }
                        return result;
                    }

                    void setup(transcript_type& transcript, const preprocessed_data_type &preprocessed_data) {
                        _etha = transcript.template challenge<field_type>();
                        _fixed_polys_values = preprocessed_data;
                    }

                    void fill_challenge_queue_for_setup(transcript_type& transcript, std::queue<value_type>& queue) {
                        // The value of _etha.
                        queue.push(transcript.template challenge<field_type>());
                    } 

                    commitment_type commit(std::size_t index) {
                        this->state_commited(index);

                        _trees[index] = nil::crypto3::zk::algorithms::precommit<fri_type>(
                            this->_polys[index], _fri_params.D[0], _fri_params.step_list.front());
                        return _trees[index].root();
                    }

                    // Should be done after commitment.
                    void mark_batch_as_fixed(std::size_t index) {
                        _batch_fixed[index] = true;
                    }

                    proof_type proof_eval(transcript_type &transcript) {
                        PROFILE_SCOPE("LPC proof eval");

                        eval_polys_and_add_roots_to_transcipt(transcript);

                        // Prepare z-s and combined_Q;
                        auto theta = transcript.template challenge<field_type>();
                        polynomial_type combined_Q = prepare_combined_Q(theta);

                        auto fri_proof = commit_and_fri_proof(combined_Q, transcript);
                        return proof_type({this->_z, fri_proof});
                    }

                    void eval_polys_and_add_roots_to_transcipt(transcript_type &transcript) {
                        PROFILE_SCOPE("LPC eval polys and add roots to transcript");
                        {
                            PROFILE_SCOPE("LPC eval polys");
                            this->eval_polys();
                        }

                        BOOST_ASSERT(this->_points.size() == this->_polys.size());
                        BOOST_ASSERT(this->_points.size() == this->_z.get_batches_num());

                        PROFILE_SCOPE("LPC add roots to transcript");

                        // For each batch we have a merkle tree.
                        for (auto const& it: this->_trees) {
                            transcript(it.second.root());
                        }
                    }

                    /** This function must be called for the cases where we want to skip the
                     * round proof for FRI. Must be called once per instance of prover for the aggregated FRI.
                     * \param[in] challenges - These challenges were sent from the "Main" prover,
                            on which the round proof was created for the polynomial F(x) = Sum(combined_Q).
                     */
                    lpc_proof_type proof_eval_lpc_proof(
                            const std::vector<typename fri_type::field_type::value_type>& challenges) {

                        typename fri_type::initial_proofs_batch_type initial_proofs =
                            nil::crypto3::zk::algorithms::query_phase_initial_proofs<fri_type, polynomial_type>(
                            this->_trees, this->_fri_params, this->_polys, challenges);
                        return {this->_z, initial_proofs};
                    }

                    /** This function must be called once for the aggregated FRI, to proof that polynomial
                        'sum_poly' has low degree.
                     * \param[in] sum_poly - polynomial F(x) = Sum(combined_Q). Can be resized before used.
                     * \param[in] transcript - This transcript is initialized on the main prover, which has digested
                            challenges from all the other provers.
                     * \returns A pair containing the FRI proof and the vector of size 'lambda' containing the challenges used.
                     */
                    void proof_eval_FRI_proof(
                            polynomial_type& sum_poly, 
                            fri_proof_type& fri_proof_out,
                            std::vector<value_type>& challenges_out,
                            typename params_type::grinding_type::output_type& proof_of_work_out,
                            transcript_type &transcript
                    ) {
                        // TODO(martun): this function belongs to FRI, not here, probably will move later.

                        // Precommit to sum_poly.
                        if constexpr(std::is_same<math::polynomial_dfs<value_type>, polynomial_type>::value ) {
                            if (sum_poly.size() != _fri_params.D[0]->size()) {
                                sum_poly.resize(_fri_params.D[0]->size(), nullptr, _fri_params.D[0]);
                            }
                        }
                        precommitment_type sum_poly_precommitment = nil::crypto3::zk::algorithms::precommit<fri_type>(
                            sum_poly,
                            _fri_params.D[0],
                            _fri_params.step_list.front()
                        );

                        std::vector<typename fri_type::precommitment_type> fri_trees;
                        std::vector<polynomial_type> fs;

                        // Contains fri_roots and final_polynomial.
                        typename fri_type::commitments_part_of_proof commitments_proof;

                        // Commit to sum_poly.
                        std::tie(fs, fri_trees, commitments_proof) =
                            nil::crypto3::zk::algorithms::commit_phase<fri_type, polynomial_type>(
                                sum_poly,
                                sum_poly_precommitment,
                                _fri_params, transcript);

                        // First grinding, then query phase.
                        proof_of_work_out = nil::crypto3::zk::algorithms::run_grinding<fri_type>(
                            _fri_params, transcript);

                        challenges_out = transcript.template challenges<typename fri_type::field_type>(
                            this->_fri_params.lambda);

                        fri_proof_out.fri_round_proof = nil::crypto3::zk::algorithms::query_phase_round_proofs<
                                fri_type, polynomial_type>(
                            _fri_params,
                            fri_trees,
                            fs,
                            commitments_proof.final_polynomial,
                            challenges_out);

                        fri_proof_out.fri_commitments_proof_part = std::move(commitments_proof);
                    }

                    typename fri_type::proof_type commit_and_fri_proof(
                            const polynomial_type& combined_Q, transcript_type &transcript) {

                        precommitment_type combined_Q_precommitment = nil::crypto3::zk::algorithms::precommit<fri_type>(
                            combined_Q,
                            _fri_params.D[0],
                            _fri_params.step_list.front()
                        );

                        typename fri_type::proof_type fri_proof = nil::crypto3::zk::algorithms::proof_eval<
                                fri_type, polynomial_type>(
                            this->_polys,
                            combined_Q,
                            this->_trees,
                            combined_Q_precommitment,
                            this->_fri_params,
                            transcript
                        );
                        return fri_proof;
                    }

                    /** \brief Computes polynomial combined_Q. In case this function changes,
                               the function 'compute_theta_power_for_combined_Q' below should be changed accordingly.
                     *  \param theta The value of challenge. When called from aggregated FRI, this values is sent from
                                the "main prover" machine.
                     *  \param starting_power When aggregated FRI is used, the value is not zero, it's the total degree of all
                                the polynomials in all the provers with indices lower than the current one.
                     */
                    polynomial_type prepare_combined_Q(
                            const typename field_type::value_type& theta,
                            std::size_t starting_power = 0) {
                        PROFILE_SCOPE("LPC prepare combined Q");
                        this->build_points_map();

                        typename field_type::value_type theta_acc = theta.pow(starting_power);
                        polynomial_type combined_Q;
                        math::polynomial<value_type> V;

                        auto points = this->get_unique_points();
                        math::polynomial<value_type> combined_Q_normal;

                        std::vector<math::polynomial<value_type>> Q_normals(points.size());

                        // We need to pre-compute what power of theta is the starting power for each itertion
                        // of the loop over the points.
                        std::vector<std::size_t> theta_powers;

                        // Write point and back indices into a vector, so it's easier to parallelize.
                        std::vector<std::pair<std::size_t, std::size_t>> point_batch_pairs;

                        // An array of the same size as point_batch_pairs, showing starting power of theta for
                        // each entry of 'point_batch_pairs'.
                        std::vector<std::size_t> theta_powers_for_each_batch;

                        theta_powers.push_back(starting_power);
                        std::size_t current_power = starting_power;
                        for (std::size_t point_index = 0; point_index < points.size(); ++point_index) {
                            for(std::size_t batch_idx = 0; batch_idx < this->_z.get_batches().size(); ++batch_idx) {
                                point_batch_pairs.push_back({point_index, batch_idx});
                                theta_powers_for_each_batch.push_back(current_power);

                                std::size_t i = this->_z.get_batches()[batch_idx];
                                for(std::size_t j = 0; j < this->_z.get_batch_size(i); j++) {
                                    if (this->_points_map[i][j].find(points[point_index]) != this->_points_map[i][j].end())
                                        current_power++;
                                }
                            }
                            theta_powers.push_back(current_power);
                        }

                        // If PolynomialType is DFS type, we need to convert this->polys to coefficients form,
                        // otherwise we do nothing. After this block polys_coefficients_ptr must be used,
                        // it will point to this->_polys if no conversion is required, or to polys_coefficients
                        // if conversion was required.
                        std::map<std::size_t,
                                 std::vector<typename PolynomialType::polynomial_type>>
                            polys_coefficients;
                        std::map<std::size_t,
                                 std::vector<typename PolynomialType::polynomial_type>>*
                            polys_coefficients_ptr;

                        if constexpr (std::is_same<math::polynomial_dfs<value_type>,
                                                   PolynomialType>::value ||
                                      std::is_same<
                                          math::polymorphic_polynomial_dfs<field_type>,
                                          PolynomialType>::value) {
                            PROFILE_SCOPE("Convert polys to coefficients form");
                            // Convert this->_polys to coefficients form.
                            std::vector<std::pair<std::size_t, std::size_t>> indices;
                            for (const auto& [i, V]: this->_polys) {
                                polys_coefficients[i].resize(V.size());
                                for (std::size_t j = 0; j < V.size(); ++j) {
                                    indices.push_back({i, j});
                                }
                            }

                            parallel_for(0, indices.size(), [this, &indices, &polys_coefficients](std::size_t i) {
                                polys_coefficients[indices[i].first][indices[i].second] =
                                    this->_polys[indices[i].first][indices[i].second].coefficients();
                            }, ThreadPool::PoolLevel::HIGH);

                            polys_coefficients_ptr = &polys_coefficients;
                        } else {
                            polys_coefficients_ptr = &this->_polys;
                        }

                        std::vector<std::vector<math::polynomial<value_type>>> Q_normal_parts(
                            points.size(), std::vector<math::polynomial<value_type>>(this->_z.get_batches().size()));

                        {
                            PROFILE_SCOPE("Compute Q normal parts");
                            parallel_for(
                                0, point_batch_pairs.size(),
                                [this, &points, &theta, &theta_powers,
                                 polys_coefficients_ptr, &point_batch_pairs,
                                 &Q_normal_parts, &theta_powers_for_each_batch](
                                    std::size_t point_batch_index) {
                                    typename field_type::value_type theta_acc = theta.pow(
                                        theta_powers_for_each_batch[point_batch_index]);
                                    std::size_t point_index =
                                        point_batch_pairs[point_batch_index].first;
                                    auto const& point = points[point_index];

                                    std::size_t i =
                                        this->_z.get_batches()
                                            [point_batch_pairs[point_batch_index].second];
                                    for (std::size_t j = 0;
                                         j < this->_z.get_batch_size(i); j++) {
                                        auto iter = this->_points_map[i][j].find(point);
                                        if (iter == this->_points_map[i][j].end())
                                            continue;

                                        auto g_normal = (*polys_coefficients_ptr)[i][j];
                                        g_normal *= theta_acc;
                                        Q_normal_parts
                                            [point_index]
                                            [point_batch_pairs[point_batch_index]
                                                 .second] += g_normal;
                                        Q_normal_parts
                                            [point_index]
                                            [point_batch_pairs[point_batch_index]
                                                 .second] -=
                                            this->_z.get(i, j, iter->second) * theta_acc;
                                        theta_acc *= theta;
                                    }
                                },
                                ThreadPool::PoolLevel::HIGH);
                        }

                        {
                            PROFILE_SCOPE("Compute Q normal");
                            parallel_for(
                                0, points.size(),
                                [this, &points, &Q_normals,
                                 &Q_normal_parts](std::size_t point_index) {
                                    math::polynomial<value_type>& Q_normal =
                                        Q_normals[point_index];

                                    for (std::size_t batch_index = 0;
                                         batch_index < this->_z.get_batches().size();
                                         ++batch_index) {
                                        Q_normal +=
                                            Q_normal_parts[point_index][batch_index];
                                    }
                                    auto const& point = points[point_index];
                                    math::polynomial<value_type> V = {-point, 1};
                                    Q_normal = Q_normal / V;
                                },
                                ThreadPool::PoolLevel::HIGH);
                        }

                        for (const auto& Q_normal: Q_normals) {
                            combined_Q_normal += Q_normal;
                        }

                        // TODO(martun): the following code is the same as above with point = _etha, de-duplicate it.
                        theta_powers = {theta_powers[points.size()]};
                        for(std::size_t i : this->_z.get_batches()) {
                            theta_powers.push_back(theta_powers.back() + this->_z.get_batch_size(i));
                        }
                        Q_normals.assign(this->_z.get_batches().size(), math::polynomial<value_type>{});

                        {
                            PROFILE_SCOPE("Compute Q normals 2 (with point = etha)");
                            parallel_for(
                                0, this->_z.get_batches().size(),
                                [this, &theta, &theta_powers, &Q_normals,
                                 polys_coefficients_ptr](std::size_t batch_idx) {
                                    std::size_t i = this->_z.get_batches()[batch_idx];
                                    typename field_type::value_type theta_acc =
                                        theta.pow(theta_powers[i]);

                                    if (_batch_fixed.find(i) == _batch_fixed.end() ||
                                        !_batch_fixed[i])
                                        return;
                                    math::polynomial<value_type>& Q_normal =
                                        Q_normals[batch_idx];
                                    auto point = _etha;
                                    math::polynomial<value_type> V = {-point, 1u};

                                    for (std::size_t j = 0;
                                         j < this->_z.get_batch_size(i); j++) {
                                        auto g_normal = (*polys_coefficients_ptr)[i][j];
                                        g_normal *= theta_acc;
                                        Q_normal += g_normal;
                                        Q_normal -= _fixed_polys_values[i][j] * theta_acc;
                                        theta_acc *= theta;
                                    }

                                    Q_normal = Q_normal / V;
                                },
                                ThreadPool::PoolLevel::HIGH);
                        }

                        for (const auto& Q_normal: Q_normals) {
                            combined_Q_normal += Q_normal;
                        }

                        if constexpr (std::is_same<math::polynomial_dfs<value_type>,
                                                   PolynomialType>::value ||
                                      std::is_same<
                                          math::polymorphic_polynomial_dfs<field_type>,
                                          PolynomialType>::value) {
                            combined_Q.from_coefficients(combined_Q_normal);
                            if (combined_Q.size() != _fri_params.D[0]->size()) {
                                combined_Q.resize(_fri_params.D[0]->size());
                            }
                        } else {
                            combined_Q = std::move(combined_Q_normal);
                        }

                        return combined_Q;
                    }

                    // Computes and returns the maximal power of theta used to compute the value of Combined_Q.
                    std::size_t compute_theta_power_for_combined_Q() {
                        std::size_t theta_power = 0;
                        this->build_points_map();

                        auto points = this->get_unique_points();

                        for (auto const &point: points) {
                            for (std::size_t i: this->_z.get_batches()) {
                                for (std::size_t j = 0; j < this->_z.get_batch_size(i); j++) {
                                    auto iter = this->_points_map[i][j].find(point);
                                    if (iter == this->_points_map[i][j].end())
                                        continue;

                                    theta_power++;
                                }
                            }
                        }

                        for (std::size_t i: this->_z.get_batches()) {
                            if (!_batch_fixed[i]) {
                                continue;
                            }

                            theta_power += this->_z.get_batch_size(i);
                        }

                        return theta_power;
                    }

                    size_t get_total_points() {
                        auto points = this->get_unique_points();

                        // List of unique eval points set. [id=>points]
                        size_t total_points = points.size();
                        if (std::any_of(_batch_fixed.begin(), _batch_fixed.end(), [](auto i){return i.second != false;}))
                            total_points++;
                        return total_points;
                    }

                    void generate_U_V_polymap(
                            typename std::vector<typename field_type::value_type>& U,
                            typename std::vector<math::polynomial<value_type>>& V,
                            typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>>& poly_map,
                            const eval_storage_type& z,
                            const value_type& theta,
                            value_type& theta_acc,
                            size_t total_points) {

                        auto points = this->get_unique_points();
                        for (std::size_t p = 0; p < points.size(); p++) {
                            auto &point = points[p];
                            V[p] = {-point, 1u};
                            for (std::size_t i:z.get_batches()) {
                                for (std::size_t j = 0; j < z.get_batch_size(i); j++) {
                                    auto it = std::find(this->_points[i][j].begin(), this->_points[i][j].end(), point);
                                    if (it == this->_points[i][j].end())
                                        continue;

                                    U[p] += this->_z.get(i, j, it - this->_points[i][j].begin()) * theta_acc;
                                    poly_map[p].push_back(std::make_tuple(i, j));
                                    theta_acc *= theta;
                                }
                            }
                        }

                        if (total_points > points.size()) {
                            std::size_t p = points.size();
                            V[p] = {-_etha, 1u};
                            for (std::size_t i:z.get_batches()) {
                                if (!_batch_fixed[i])
                                    continue;
                                for (std::size_t j = 0; j < z.get_batch_size(i); j++) {
                                    U[p] += _fixed_polys_values[i][j] * theta_acc;
                                    poly_map[p].push_back(std::make_tuple(i, j));
                                    theta_acc *= theta;
                                }
                            }
                        }
                    }

                    bool verify_eval(
                        const proof_type &proof,
                        const std::map<std::size_t, commitment_type> &commitments,
                        transcript_type &transcript
                    ) {
                        PROFILE_SCOPE("LPC verify eval");
                        this->_z = proof.z;
                        for (auto const &it: commitments) {
                            transcript(commitments.at(it.first));
                        }

                        size_t total_points = get_total_points();
                        typename std::vector<typename field_type::value_type> U(total_points);

                        // V is product of (x - eval_point) polynomial for each eval_point
                        typename std::vector<math::polynomial<value_type>> V(total_points);

                        // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                        typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> poly_map(total_points);

                        value_type theta = transcript.template challenge<field_type>();
                        value_type theta_acc = value_type::one();

                        generate_U_V_polymap(U, V, poly_map, proof.z, theta, theta_acc, total_points);

                        return nil::crypto3::zk::algorithms::verify_eval<fri_type>(
                            proof.fri_proof,
                            _fri_params,
                            commitments,
                            theta,
                            poly_map,
                            U,
                            V,
                            transcript
                        );
                    }

                    // Params for LPC are actually FRI params. We can return some LPC params from here in the future if needed.
                    // This params are used for initializing transcript in the prover.
                    const params_type& get_commitment_params() const {
                        return _fri_params;
                    }

                    boost::property_tree::ptree get_params() const{
                        boost::property_tree::ptree params;
                        params.put("type", "LPC");
                        params.put("r", _fri_params.r);
                        params.put("m", fri_type::m);
                        params.put("max_degree", _fri_params.max_degree);

                        boost::property_tree::ptree step_list_node;
                        for( std::size_t j = 0; j < _fri_params.step_list.size(); j++){
                            boost::property_tree::ptree step_node;
                            step_node.put("", _fri_params.step_list[j]);
                            step_list_node.push_back(std::make_pair("", step_node));
                        }
                        params.add_child("step_list", step_list_node);

                        boost::property_tree::ptree D_omegas_node;
                        for(std::size_t j = 0; j < _fri_params.D.size(); j++){
                            boost::property_tree::ptree D_omega_node;
                            D_omega_node.put("", _fri_params.D[j]->get_domain_element(1));
                            D_omegas_node.push_back(std::make_pair("", D_omega_node));
                        }
                        params.add_child("D_omegas", D_omegas_node);
                        return params;
                    }

                    bool operator==(const lpc_commitment_scheme& rhs) const = default;
                };

                template<typename MerkleTreeHashType, typename TranscriptHashType,
                        std::size_t M, typename GrindingType = proof_of_work<TranscriptHashType>>
                struct list_polynomial_commitment_params {
                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t m = M;
                    typedef GrindingType grinding_type;
                };

                /**
                 * @brief Based on the FRI Commitment description from \[RedShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[Placeholder].
                 *
                 * References:
                 * \[Placeholder]:
                 * "PLACEHOLDER: Transparent SNARKs from List
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment;

                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment : public detail::basic_batched_fri<
                    FieldType,
                    typename LPCParams::merkle_hash_type,
                    typename LPCParams::transcript_hash_type,
                    LPCParams::m,
                    typename LPCParams::grinding_type
                > {
                    using fri_type = typename detail::basic_batched_fri<
                        FieldType,
                        typename LPCParams::merkle_hash_type,
                        typename LPCParams::transcript_hash_type,
                        LPCParams::m,
                        typename LPCParams::grinding_type
                    >;
                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const bool is_const_size = LPCParams::is_const_size;
                    constexpr static const bool is_batched_list_polynomial_commitment = true;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    // TODO(martun): this duplicates type 'fri_type', please de-duplicate.
                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                            typename LPCParams::transcript_hash_type,
                            LPCParams::m,
                            typename LPCParams::grinding_type>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;
                    using field_type = FieldType;
                    using polynomials_values_type = typename basic_fri::polynomials_values_type;
                    using params_type = typename basic_fri::params_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<typename LPCParams::transcript_hash_type>;
                    using transcript_hash_type = typename LPCParams::transcript_hash_type;
                    using eval_storage_type = eval_storage<field_type>;

                    struct proof_type {
                        eval_storage_type z;
                        typename basic_fri::proof_type fri_proof;

                        bool operator==(const proof_type& rhs) const = default;
                    };

                    // Represents an initial proof, which must be created for each of the N provers.
                    struct lpc_proof_type {
                        eval_storage_type z;
                        typename basic_fri::initial_proofs_batch_type initial_fri_proofs;

                        bool operator==(const lpc_proof_type& rhs) const = default;
                    };

                    // Represents a round proof, which must be created just once on the main prover.
                    struct fri_proof_type {
                        // We have a single round proof for checking that F(X) is a low degree polynomial.
                        typename basic_fri::round_proofs_batch_type fri_round_proof;

                        // Contains fri_roots and final_polynomial that correspond to the polynomial F(x).
                        typename basic_fri::commitments_part_of_proof fri_commitments_proof_part;

                        bool operator==(const fri_proof_type& rhs) const = default;
                    };

                    // A single instance of this class will store all the LPC proofs for a group of provers
                    // when aggregated FRI is used.
                    struct aggregated_proof_type {
                        // We have a single round proof for checking that F(X) is a low degree polynomial.
                        fri_proof_type fri_proof;

                        // For each prover we have an initial proof.
                        std::vector<lpc_proof_type> initial_proofs_per_prover;

                        typename LPCParams::grinding_type::output_type proof_of_work;

                        bool operator==(const aggregated_proof_type& rhs) const = default;
                    };
                };

                template<typename FieldType, typename LPCParams>
                using list_polynomial_commitment = batched_list_polynomial_commitment<FieldType, LPCParams>;
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
