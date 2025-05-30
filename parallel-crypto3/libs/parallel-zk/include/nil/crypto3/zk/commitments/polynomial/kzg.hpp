//-----------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef PARALLEL_CRYPTO3_ZK_COMMITMENTS_KZG_HPP
#define PARALLEL_CRYPTO3_ZK_COMMITMENTS_KZG_HPP

#ifdef CRYPTO3_ZK_COMMITMENTS_KZG_HPP
#error "You're mixing parallel and non-parallel crypto3 versions"
#endif

#include <tuple>
#include <vector>
#include <set>
#include <queue>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/iterator/zip_iterator.hpp>
#include <boost/accumulators/accumulators.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/hash/block_to_field_elements_wrapper.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/batched_commitment.hpp>

using namespace nil::crypto3::math;

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                /**
                 * @brief The KZG Polynomial Commitment with Fiat-Shamir heuristic.
                 *
                 * References:
                 * "Constant-Size Commitments to Polynomials and Their Applications",
                 * Aniket Kate, Gregory M. Zaverucha, and Ian Goldberg,
                 * <https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf>
                 */
                template<typename CurveType>
                struct kzg {

                    typedef CurveType curve_type;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using field_type = typename curve_type::scalar_field_type;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using single_commitment_type = std::vector<typename curve_type::template g1_type<>::value_type>;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using commitment_type = typename curve_type::template g1_type<>::value_type;
                    using proof_type = commitment_type;

                    struct params_type {
                        using commitment_type = typename curve_type::template g1_type<>::value_type;
                        using field_type = typename curve_type::scalar_field_type;
                        using params_single_commitment_type = single_commitment_type;
                        using params_verification_key_type = verification_key_type;

                        single_commitment_type commitment_key;
                        verification_key_type verification_key;

                        params_type() {}

                        params_type(std::size_t d) {
                            auto alpha = algebra::random_element<field_type>();
                            verification_key = verification_key_type::one() * alpha;
                            commitment_key.resize(d);
                            auto alpha_com = commitment_type::one();
                            for (std::size_t i = 0; i < d; i++) {
                                commitment_key[i] = alpha_com;
                                alpha_com = alpha * alpha_com;
                            }
                        }

                        params_type(std::size_t d, scalar_value_type alpha) {
                            verification_key = verification_key_type::one() * alpha;
                            commitment_key.resize(d);
                            auto alpha_com = commitment_type::one();
                            for (std::size_t i = 0; i < d; i++) {
                                commitment_key[i] = alpha_com;
                                alpha_com = alpha * alpha_com;
                            }
                        }

                        params_type(single_commitment_type ck, verification_key_type vk) :
                                commitment_key(ck), verification_key(vk) {}
                    };

                    struct public_key_type {
                        commitment_type commit;
                        scalar_value_type z;
                        scalar_value_type eval;

                        public_key_type() = default;

                        public_key_type(commitment_type c, scalar_value_type z, scalar_value_type e)
                                : commit(c), z(z), eval(e) {}

                        public_key_type &operator=(const public_key_type &other) = default;
                    };
                };
            } // namespace commitments

            namespace algorithms {
                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::kzg<typename CommitmentSchemeType::curve_type>, CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::commitment_type
                commit(const typename CommitmentSchemeType::params_type &params,
                       const typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> &f) {
                    BOOST_ASSERT(f.size() <= params.commitment_key.size());
                    return algebra::multiexp<typename CommitmentSchemeType::multiexp_method>(
                            params.commitment_key.begin(),
                            params.commitment_key.begin() + f.size(),
                            f.begin(), f.end(), 1);
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::kzg<typename CommitmentSchemeType::curve_type>, CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::proof_type
                proof_eval(typename CommitmentSchemeType::params_type params,
                           const typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> &f,
                           typename CommitmentSchemeType::scalar_value_type z) {

                    // We need two scopes on the next line to force it to use the initializer list version,
                    // not another constructor with 2 params.
                    const typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> denominator_polynom = {
                            {-z, CommitmentSchemeType::scalar_value_type::one()}};

                    typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> q(f);
                    q[0] -= f.evaluate(z);
                    auto r = q % denominator_polynom;
                    if (!r.is_zero()) {
                        throw std::runtime_error("incorrect eval or point z");
                    }
                    q /= denominator_polynom;

                    return commit<CommitmentSchemeType>(params, q);
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::kzg<typename CommitmentSchemeType::curve_type>, CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::proof_type
                proof_eval(typename CommitmentSchemeType::params_type params,
                           const typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> &f,
                           typename CommitmentSchemeType::public_key_type &pk) {

                    return proof_eval<CommitmentSchemeType>(params, f, pk.z);
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::kzg<typename CommitmentSchemeType::curve_type>, CommitmentSchemeType>::value,
                                bool>::type = true>
                static bool verify_eval(const typename CommitmentSchemeType::params_type &params,
                                        const typename CommitmentSchemeType::proof_type &proof,
                                        const typename CommitmentSchemeType::public_key_type &public_key) {

                    auto A_1 = algebra::precompute_g1<typename CommitmentSchemeType::curve_type>(proof);
                    auto A_2 = algebra::precompute_g2<typename CommitmentSchemeType::curve_type>(
                            params.verification_key -
                            public_key.z *
                            CommitmentSchemeType::curve_type::template g2_type<>::value_type::one());
                    auto B_1 = algebra::precompute_g1<typename CommitmentSchemeType::curve_type>(
                            public_key.eval * CommitmentSchemeType::curve_type::template g1_type<>::value_type::one() -
                            public_key.commit);
                    auto B_2 = algebra::precompute_g2<typename CommitmentSchemeType::curve_type>(
                            CommitmentSchemeType::curve_type::template g2_type<>::value_type::one());

                    typename CommitmentSchemeType::gt_value_type gt3 =
                        algebra::double_miller_loop<typename CommitmentSchemeType::curve_type>( A_1, A_2, B_1, B_2);
                    std::optional<typename CommitmentSchemeType::gt_value_type> gt_4 =
                        algebra::final_exponentiation<typename CommitmentSchemeType::curve_type>(gt3);

                    if (!gt_4) {
                        return false;
                    }

                    return *gt_4 == CommitmentSchemeType::gt_value_type::one();
                }
            } // namespace algorithms

            namespace commitments {
                /**
                 * @brief Based on the KZG Commitment from [KZG10].
                 *
                 * References:
                 * "Efficient polynomial commitment schemes for
                 * multiple points and polynomials",
                 * Dan Boneh, Justin Drake, Ben Fisch,
                 * <https://eprint.iacr.org/2020/081.pdf>
                 */
                template<typename CurveType, typename TranscriptHashType,
                        typename PolynomialType = math::polynomial_dfs<typename CurveType::scalar_field_type::value_type>>
                struct batched_kzg {

                    constexpr static bool is_kzg = true;

                    typedef CurveType curve_type;
                    typedef TranscriptHashType transcript_hash_type;
                    typedef typename curve_type::gt_type::value_type gt_value_type;

                    using multiexp_method = typename algebra::policies::multiexp_method_BDLO12;
                    using field_type = typename curve_type::scalar_field_type;
                    using scalar_value_type = typename curve_type::scalar_field_type::value_type;
                    using single_commitment_type = typename curve_type::template g1_type<>::value_type;
                    using verification_key_type = typename curve_type::template g2_type<>::value_type;
                    using polynomial_type = PolynomialType;
                    using batch_of_polynomials_type = std::vector<polynomial_type>;
                    using evals_type = std::vector<std::vector<scalar_value_type>>;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
                    using multi_commitment_type = std::vector<single_commitment_type>;

                    using commitment_type = std::vector<std::uint8_t>; // Used in placeholder because it's easy to push it into transcript

                    using eval_storage_type = eval_storage<field_type>;

                    struct proof_type {
                        eval_storage_type z;
                        single_commitment_type kzg_proof;
                    };

                    struct params_type {
                        using commitment_type = std::vector<std::uint8_t>;
                        using field_type = typename curve_type::scalar_field_type;

                        std::vector<single_commitment_type> commitment_key;
                        std::vector<verification_key_type> verification_key;
                        using params_single_commitment_type = commitment_type;

                        params_type() {};

                        params_type(std::size_t d, std::size_t t) {
                            auto alpha = algebra::random_element<typename curve_type::scalar_field_type>();
                            commitment_key.resize(d);
                            verification_key.resize(t + 1);
                            auto alpha_comm = single_commitment_type::one();
                            for (std::size_t i = 0; i < d; ++i) {
                                commitment_key[i] = alpha_comm;
                                alpha_comm *= alpha;
                            }
                            auto alpha_ver = verification_key_type::one();
                            for (std::size_t i = 0; i <= t; ++i) {
                                verification_key[i] = alpha_ver;
                                alpha_ver *= alpha;
                            }
                        }

                        params_type(std::size_t d, std::size_t t, scalar_value_type alpha) {
                            commitment_key.resize(d);
                            verification_key.resize(t + 1);
                            auto alpha_comm = single_commitment_type::one();
                            for (std::size_t i = 0; i < d; ++i) {
                                commitment_key[i] = alpha_comm;
                                alpha_comm = alpha * alpha_comm;
                            }
                            auto alpha_ver = verification_key_type::one();
                            for (std::size_t i = 0; i <= t; ++i) {
                                verification_key[i] = alpha_ver;
                                alpha_ver = alpha * alpha_ver;
                            }
                        }

                        params_type(std::vector<single_commitment_type> commitment_key,
                                    std::vector<verification_key_type> verification_key) :
                                commitment_key(commitment_key), verification_key(verification_key) {};

                        params_type operator=(const params_type &other) {
                            commitment_key = other.commitment_key;
                            verification_key = other.verification_key;
                            return *this;
                        }
                    };

                    struct public_key_type {
                        std::vector<single_commitment_type> commits;
                        std::vector<scalar_value_type> T;  // merged eval points
                        std::vector<std::vector<scalar_value_type>> S; // eval points
                        std::vector<polynomial_type> r; // U polynomials
                        public_key_type() {};

                        public_key_type(const std::vector<single_commitment_type> &commits,
                                        const std::vector<scalar_value_type> &T,
                                        const std::vector<std::vector<scalar_value_type>> &S,
                                        const std::vector<polynomial_type> &r) :
                                commits(commits), T(T), S(S), r(r) {};

                        public_key_type operator=(const public_key_type &other) {
                            commits = other.commits;
                            T = other.T;
                            S = other.S;
                            r = other.r;
                            return *this;
                        }
                    };
                };
            } // namespace commitments

            namespace algorithms {
                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static void update_transcript(const typename CommitmentSchemeType::public_key_type &public_key,
                                              typename CommitmentSchemeType::transcript_type &transcript) {

                    /* The procedure of updating the transcript is subject to review and change
                     * #295 */


                    for (const auto &commit : public_key.commits) {
                        transcript(commit);
                    }
                    for (const auto &S : public_key.S) {
                        for (const auto &s : S) {
                            transcript(s);
                        }
                    }
                    for (const auto &r: public_key.r) {
                        for (std::size_t i = 0; i < r.size(); ++i) {
                            transcript(r[i]);
                        }
                    }
                }

                // Duplicates get_U functions logic
                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>, CommitmentSchemeType>::value,
                                bool
                        >::type = true
                >
                static std::vector<typename CommitmentSchemeType::polynomial_type>
                create_evals_polys(const typename CommitmentSchemeType::batch_of_polynomials_type &polys,
                                   const std::vector<std::vector<typename CommitmentSchemeType::scalar_value_type>> S) {
                    BOOST_ASSERT(polys.size() == S.size());
                    std::vector<typename CommitmentSchemeType::polynomial_type> rs(polys.size());
                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        typename std::vector<std::pair<typename CommitmentSchemeType::scalar_value_type, typename CommitmentSchemeType::scalar_value_type>> evals;
                        for (auto s: S[i]) {
                            evals.push_back(std::make_pair(s, polys[i].evaluate(s)));
                        }
                        rs[i] = math::lagrange_interpolation(evals);
                    }
                    return rs;
                }

                template<typename CommitmentSchemeType, typename PolynomialType=typename CommitmentSchemeType::polynomial_type,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<
                                                typename CommitmentSchemeType::curve_type,
                                                typename CommitmentSchemeType::transcript_hash_type,
                                                PolynomialType
                                        >,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::single_commitment_type
                commit_one(const typename CommitmentSchemeType::params_type &params,
                           const typename math::polynomial<typename CommitmentSchemeType::field_type::value_type> &poly) {
                    BOOST_ASSERT(poly.size() <= params.commitment_key.size());
                    return algebra::multiexp<typename CommitmentSchemeType::multiexp_method>(
                            params.commitment_key.begin(),
                            params.commitment_key.begin() + poly.size(),
                            poly.begin(), poly.end(), 1
                    );
                }

                template<typename CommitmentSchemeType, typename PolynomialType=typename CommitmentSchemeType::polynomial_type,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type, PolynomialType>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::single_commitment_type commit_one(
                        const typename CommitmentSchemeType::params_type &params,
                        const typename math::polynomial_dfs<typename CommitmentSchemeType::field_type::value_type> &poly) {
                    auto poly_normal = poly.coefficients();
                    BOOST_ASSERT(poly_normal.size() <= params.commitment_key.size());
                    return algebra::multiexp<typename CommitmentSchemeType::multiexp_method>(
                            params.commitment_key.begin(),
                            params.commitment_key.begin() +
                            poly_normal.size(), poly_normal.begin(),
                            poly_normal.end(), 1);
                }


                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<
                                                typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type,
                                                math::polynomial<typename CommitmentSchemeType::field_type::value_type>>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::multi_commitment_type
                commit(const typename CommitmentSchemeType::params_type &params,
                       const std::vector<math::polynomial<typename CommitmentSchemeType::field_type::value_type>> &polys) {
                    typename CommitmentSchemeType::multi_commitment_type commitments;

                    commitments.resize(polys.size());
                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        BOOST_ASSERT(polys[i].size() <= params.commitment_key.size());
                        commitments[i] = commit_one<CommitmentSchemeType>(params, polys[i]);
                    }
                    return commitments;
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::multi_commitment_type
                commit(const typename CommitmentSchemeType::params_type &params,
                       const std::vector<math::polynomial_dfs<typename CommitmentSchemeType::field_type::value_type>> &polys) {
                    typename CommitmentSchemeType::multi_commitment_type commitments;
                    commitments.resize(polys.size());
                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        BOOST_ASSERT(polys[i].size() <= params.commitment_key.size());
                        commitments[i] = commit_one<CommitmentSchemeType>(params, polys[i]);
                    }
                    return commitments;
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type,
                                                typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static std::vector<typename CommitmentSchemeType::scalar_value_type>
                merge_eval_points(std::vector<std::vector<typename CommitmentSchemeType::scalar_value_type>> S) {
                    std::set<typename CommitmentSchemeType::scalar_value_type> result;
                    for (std::size_t i = 0; i < S.size(); ++i) {
                        result.insert(S[i].begin(), S[i].end());
                    }
                    return std::vector<typename CommitmentSchemeType::scalar_value_type>(result.begin(), result.end());
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::verification_key_type commit_g2(
                        typename CommitmentSchemeType::params_type &params,
                        typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> poly) {
                    BOOST_ASSERT(poly.size() <= params.verification_key.size());
                    typename CommitmentSchemeType::verification_key_type result;
                    auto it1 = params.verification_key.begin();
                    auto it2 = params.verification_key.begin() + poly.size();
                    result = algebra::multiexp<typename CommitmentSchemeType::multiexp_method>(
                            it1, it2,
                            poly.begin(), poly.end(), 1
                    );
                    return result;
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type, typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>
                create_polynom_by_zeros(const std::vector<typename CommitmentSchemeType::scalar_value_type> S) {
                    assert(S.size() > 0);
                    typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> Z = {
                            {-S[0], CommitmentSchemeType::scalar_value_type::one()}};
                    for (std::size_t i = 1; i < S.size(); ++i) {
                        Z *= typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                {-S[i], CommitmentSchemeType::scalar_value_type::one()});
                    }
                    return Z;
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type,
                                                typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>
                set_difference_polynom(std::vector<typename CommitmentSchemeType::scalar_value_type> T,
                                       std::vector<typename CommitmentSchemeType::scalar_value_type> S) {
                    std::sort(T.begin(), T.end());
                    std::sort(S.begin(), S.end());
                    std::vector<typename CommitmentSchemeType::scalar_value_type> result;
                    std::set_difference(T.begin(), T.end(), S.begin(), S.end(), std::back_inserter(result));
                    if (result.size() == 0) {
                        return typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                {{CommitmentSchemeType::scalar_value_type::one()}});
                    }
                    return create_polynom_by_zeros<CommitmentSchemeType>(result);
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type,
                                                typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static typename CommitmentSchemeType::single_commitment_type
                proof_eval(const typename CommitmentSchemeType::params_type &params,
                           const typename CommitmentSchemeType::batch_of_polynomials_type &polys,
                           typename CommitmentSchemeType::public_key_type &public_key,
                           typename CommitmentSchemeType::transcript_type &transcript) {
                    update_transcript<CommitmentSchemeType>(public_key, transcript);

                    auto gamma = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                    auto factor = CommitmentSchemeType::scalar_value_type::one();
                    typename CommitmentSchemeType::polynomial_type accum;

                    for (std::size_t i = 0; i < polys.size(); ++i) {
                        auto spare_poly = polys[i] - public_key.r[i];
                        auto denom = create_polynom_by_zeros<CommitmentSchemeType>(public_key.S[i]);
                        for (auto s: public_key.S[i]) {
                            assert(spare_poly.evaluate(s).is_zero());
                            assert(denom.evaluate(s).is_zero());
                        }
                        assert(spare_poly % denom ==
                               typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                       {{CommitmentSchemeType::scalar_value_type::zero()}}));
                        spare_poly /= denom;
                        accum += spare_poly * factor;
                        factor *= gamma;
                    }

                    //verify without pairing
                    /*
                    {
                        typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> right_side({{0}});
                        factor = CommitmentSchemeType::scalar_value_type::one();
                        for (std::size_t i = 0; i < polys.size(); ++i) {
                            right_side = right_side + factor * (polys[i] - public_key.r[i]) * set_difference_polynom<CommitmentSchemeType>(public_key.T, public_key.S[i]);
                            factor = factor * gamma;
                        }
                        assert(accum * create_polynom_by_zeros<CommitmentSchemeType>(public_key.T) == right_side);
                    }*/

                    return commit_one<CommitmentSchemeType>(params, accum);
                }

                template<typename CommitmentSchemeType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::batched_kzg<typename CommitmentSchemeType::curve_type,
                                                typename CommitmentSchemeType::transcript_hash_type, typename CommitmentSchemeType::polynomial_type>,
                                        CommitmentSchemeType>::value,
                                bool>::type = true>
                static bool verify_eval(typename CommitmentSchemeType::params_type params,
                                        const typename CommitmentSchemeType::single_commitment_type &proof,
                                        const typename CommitmentSchemeType::public_key_type &public_key,
                                        typename CommitmentSchemeType::transcript_type &transcript) {
                    update_transcript<CommitmentSchemeType>(public_key, transcript);

                    auto gamma = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                    auto factor = CommitmentSchemeType::scalar_value_type::one();
                    auto left_side_pairing = CommitmentSchemeType::gt_value_type::one();

                    for (std::size_t i = 0; i < public_key.commits.size(); ++i) {
                        auto r_commit = commit_one<CommitmentSchemeType>(params, public_key.r[i]);
                        auto left = factor * (public_key.commits[i] - r_commit);
                        auto right = commit_g2<CommitmentSchemeType>(params,
                                                                     set_difference_polynom<CommitmentSchemeType>(
                                                                             public_key.T, public_key.S[i]));
                        if (public_key.commits.size() == 1) {
                            assert(right == CommitmentSchemeType::verification_key_type::one());
                        }

                        auto left_right = algebra::pair_reduced<typename CommitmentSchemeType::curve_type>(left, right);
                        if (!left_right) {
                            return false;
                        }
                        left_side_pairing = left_side_pairing * (*left_right);
                        factor = factor * gamma;
                    }

                    auto right = commit_g2<CommitmentSchemeType>(params, create_polynom_by_zeros<CommitmentSchemeType>( public_key.T));
                    auto right_side_pairing = algebra::pair_reduced<typename CommitmentSchemeType::curve_type>(proof, right);

                    if (!right_side_pairing) {
                        return false;
                    }

                    return left_side_pairing == *right_side_pairing;
                }
            } // namespace algorithms


            namespace commitments {
                // Placeholder-friendly class
                template<typename CommitmentSchemeType>
                class kzg_commitment_scheme :
                        public polys_evaluator<
                                typename CommitmentSchemeType::params_type,
                                typename CommitmentSchemeType::commitment_type,
                                typename CommitmentSchemeType::polynomial_type> {
                public:
                    using curve_type = typename CommitmentSchemeType::curve_type;
                    using field_type = typename CommitmentSchemeType::field_type;
                    using params_type = typename CommitmentSchemeType::params_type;
                    using value_type = typename field_type::value_type;

                    // This should be marshallable and transcriptable type
                    using commitment_type = typename CommitmentSchemeType::commitment_type;
                    using transcript_type = typename CommitmentSchemeType::transcript_type;
                    using transcript_hash_type = typename CommitmentSchemeType::transcript_hash_type;
                    using polynomial_type = typename CommitmentSchemeType::polynomial_type;
                    using proof_type = typename CommitmentSchemeType::proof_type;
                    using endianness = nil::crypto3::marshalling::option::big_endian;
                private:
                    params_type _params;
                    std::map<std::size_t, commitment_type> _commitments;
                    std::map<std::size_t, std::vector<typename CommitmentSchemeType::single_commitment_type>> _ind_commitments;
                    std::vector<typename CommitmentSchemeType::scalar_value_type> _merged_points;
                protected:
                    typename CommitmentSchemeType::verification_key_type
                    commit_g2(typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> poly) {
                        BOOST_ASSERT(poly.size() <= _params.verification_key.size());
                        auto result = algebra::multiexp<typename CommitmentSchemeType::multiexp_method>(
                                _params.verification_key.begin(),
                                _params.verification_key.begin() + poly.size(), poly.begin(), poly.end(), 1);
                        return result;
                    }

                    // Differs from static one by input parameters
                    void merge_eval_points() {
                        std::set<typename CommitmentSchemeType::scalar_value_type> set;
                        for (auto const &it: this->_points) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_points[k].size(); ++i) {
                                set.insert(this->_points[k][i].begin(), this->_points[k][i].end());
                            }
                        }
                        _merged_points = std::vector<typename CommitmentSchemeType::scalar_value_type>(set.begin(),
                                                                                                       set.end());
                    }

                    typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>
                    set_difference_polynom(
                            std::vector<typename CommitmentSchemeType::scalar_value_type> merged_points,
                            std::vector<typename CommitmentSchemeType::scalar_value_type> points) {
                        std::sort(merged_points.begin(), merged_points.end());
                        std::sort(points.begin(), points.end());
                        std::vector<typename CommitmentSchemeType::scalar_value_type> result;
                        std::set_difference(merged_points.begin(), merged_points.end(), points.begin(), points.end(),
                                            std::back_inserter(result));
                        if (result.size() == 0) {
                            return typename math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                    {{CommitmentSchemeType::scalar_value_type::one()}});
                        }
                        BOOST_ASSERT(this->get_V(result) * this->get_V(points) == this->get_V(merged_points));
                        return this->get_V(result);
                    }

                    void update_transcript(std::size_t batch_ind,
                                           typename CommitmentSchemeType::transcript_type &transcript) {
                        /* The procedure of updating the transcript is subject to review and change
                         * #295 */

                        // Push commitments to transcript

                        transcript(_commitments[batch_ind]);

                        // Push evaluation points to transcript
                        for(std::size_t i = 0; i < this->_z.get_batch_size(batch_ind); i++) {
                            for(std::size_t j = 0; j < this->_z.get_poly_points_number(batch_ind, i); j++) {
                                transcript(this->_z.get(batch_ind, i, j));
                            }
                        }

                        // Push U polynomials to transcript
                        for (std::size_t i = 0; i < this->_points[batch_ind].size(); i++) {
                            auto poly = this->get_U(batch_ind, i);
                            for (std::size_t j = 0; j < poly.size(); ++j) {
                                transcript(poly[j]);
                            }
                        }
                    }

                public:
                    using preprocessed_data_type = bool;

                    // Interface functions, not useful here. Added for compatibility with LPC.
                    void mark_batch_as_fixed(std::size_t index) {
                    }
                    void set_fixed_polys_values(const preprocessed_data_type& value) {
                    }

                    kzg_commitment_scheme(params_type kzg_params) : _params(kzg_params) {}

                    // Differs from static, because we pack the result into byte blob.
                    commitment_type commit(std::size_t index) {
                        this->_ind_commitments[index] = {};
                        this->state_commited(index);

                        std::vector<std::uint8_t> result;
                        for (std::size_t i = 0; i < this->_polys[index].size(); ++i) {
                            BOOST_ASSERT(this->_polys[index][i].degree() <= _params.commitment_key.size());
                            auto single_commitment = nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>(
                                    _params,
                                    this->_polys[index][i]);
                            this->_ind_commitments[index].push_back(single_commitment);
                            nil::crypto3::marshalling::status_type status;
                            std::vector<uint8_t> single_commitment_bytes =
                                    nil::crypto3::marshalling::pack<endianness>(single_commitment, status);
                            THROW_IF_ERROR_STATUS(status, "kzg::commit");
                            result.insert(result.end(), single_commitment_bytes.begin(), single_commitment_bytes.end());
                        }
                        _commitments[index] = result;
                        return result;
                    }

                    preprocessed_data_type preprocess(transcript_type &transcript) const {
                        return true;
                    }

                    void setup(transcript_type &transcript, preprocessed_data_type b = true) {
                        // Nothing to be done here.
                    }

                    void fill_challenge_queue_for_setup(transcript_type& transcript, std::queue<value_type>& queue) {
                        // Nothing to be done here.
                    }

                    proof_type proof_eval(transcript_type &transcript) {
                        this->eval_polys();
                        this->merge_eval_points();

                        for (auto const &it: this->_commitments) {
                            auto k = it.first;
                            update_transcript(k, transcript);
                        }

                        auto gamma = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                        auto factor = CommitmentSchemeType::scalar_value_type::one();
                        typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> accum =
                                {{CommitmentSchemeType::scalar_value_type::zero()}};

                        for (auto const &it: this->_polys) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_z.get_batch_size(k); ++i) {
                                accum += factor * (math::polynomial<typename CommitmentSchemeType::scalar_value_type>(
                                        this->_polys[k][i].coefficients()) - this->get_U(k, i)) /
                                         this->get_V(this->_points[k][i]);
                                factor *= gamma;
                            }
                        }

                        //verify without pairing. It's only for debug
                        //if something goes wrong, it may be useful to place here verification with pairings
                        /*
                        {
                            typename math::polynomial<typename CommitmentSchemeType::scalar_value_type> right_side({{0}});
                            factor = CommitmentSchemeType::scalar_value_type::one();
                            for( auto const &it: this->_polys ){
                                auto k = it.first;
                                for (std::size_t i = 0; i < this->_points[k].size(); ++i) {
                                    right_side = right_side + (factor * (math::polynomial<typename CommitmentSchemeType::scalar_value_type>(this->_polys[k][i].coefficients()) - this->get_U(k, i)) *
                                        set_difference_polynom(this->_merged_points, this->_points[k][i]));
                                    factor = factor * gamma;
                                }
                            }
                            assert(accum * this->get_V(this->_merged_points) == right_side);
                        }*/
                        return {this->_z,
                                nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>(_params, accum)};
                    }

                    bool verify_eval(const proof_type &proof,
                                     const std::map<std::size_t, commitment_type> &commitments,
                                     transcript_type &transcript) {
                        this->merge_eval_points();
                        this->_commitments = commitments;
                        this->_z = proof.z;

                        for (auto const &it: this->_commitments) {
                            auto k = it.first;
                            update_transcript(k, transcript);
                        }

                        auto gamma = transcript.template challenge<typename CommitmentSchemeType::curve_type::scalar_field_type>();
                        auto factor = CommitmentSchemeType::scalar_value_type::one();
                        auto left_side_accum = CommitmentSchemeType::gt_value_type::one();

                        for (const auto &it: this->_commitments) {
                            auto k = it.first;
                            for (std::size_t i = 0; i < this->_points.at(k).size(); ++i) {
                                std::size_t blob_size = this->_commitments.at(k).size() / this->_points.at(k).size();
                                std::vector<std::uint8_t> byteblob(blob_size);

                                for (std::size_t j = 0; j < blob_size; j++) {
                                    byteblob[j] = this->_commitments.at(k)[i * blob_size + j];
                                }
                                nil::crypto3::marshalling::status_type status;
                                typename curve_type::template g1_type<>::value_type
                                        i_th_commitment = nil::crypto3::marshalling::pack(byteblob, status);
                                THROW_IF_ERROR_STATUS(status, "kzg::verify_eval");
                                auto U_commit = nil::crypto3::zk::algorithms::commit_one<CommitmentSchemeType>
                                    (_params, this->get_U(k, i));

                                auto diffpoly = set_difference_polynom(_merged_points, this->_points.at(k)[i]);
                                auto diffpoly_commitment = commit_g2(diffpoly);

                                auto left_side_pairing = nil::crypto3::algebra::pair_reduced<curve_type>
                                    (factor * (i_th_commitment - U_commit), diffpoly_commitment);
                                if (!left_side_pairing) {
                                    return false;
                                }

                                left_side_accum = left_side_accum * (*left_side_pairing);
                                factor *= gamma;
                            }
                        }

                        auto right_side_pairing = algebra::pair_reduced<typename CommitmentSchemeType::curve_type>(
                                proof.kzg_proof,
                                commit_g2(this->get_V(this->_merged_points))
                        );

                        if (!right_side_pairing) {
                            return false;
                        }

                        return left_side_accum == *right_side_pairing;
                    }

                    const params_type &get_commitment_params() const {
                        return _params;
                    }
                };
            }     // namespace commitments
        }         // namespace zk
    }             // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_KZG_HPP
