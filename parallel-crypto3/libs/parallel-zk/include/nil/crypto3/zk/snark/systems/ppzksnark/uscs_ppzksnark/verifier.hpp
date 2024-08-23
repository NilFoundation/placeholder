//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/arithmetization/arithmetic_programs/ssp.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/uscs.hpp>
#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/uscs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                using namespace algebra;

                /*
                 Below are four variants of verifier algorithm for the USCS ppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                 verification key. In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= CS.num_inputs (and
                     the primary input is implicitly padded with zeros up to length CS.num_inputs).
                 */

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_process_verification_key {
                    typedef detail::uscs_ppzksnark_policy<CurveType> policy_type;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;

                public:
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    static inline processed_verification_key_type process(const verification_key_type &vk) {

                        processed_verification_key_type pvk;

                        pvk.pp_G1_one_precomp = precompute_g1<CurveType>(g1_type::value_type::one());
                        pvk.pp_G2_one_precomp = precompute_g2<CurveType>(g2_type::value_type::one());

                        pvk.vk_tilde_g2_precomp = precompute_g2<CurveType>(vk.tilde_g2);
                        pvk.vk_alpha_tilde_g2_precomp = precompute_g2<CurveType>(vk.alpha_tilde_g2);
                        pvk.vk_Z_g2_precomp = precompute_g2<CurveType>(vk.Z_g2);

                        pvk.pairing_of_g1_and_g2 = miller_loop<CurveType>(pvk.pp_G1_one_precomp, pvk.pp_G2_one_precomp);

                        pvk.encoded_IC_query = vk.encoded_IC_query;

                        return pvk;
                    }
                };

                template<typename CurveType>
                class uscs_ppzksnark_verifier_weak_input_consistency {
                    typedef detail::uscs_ppzksnark_policy<CurveType> policy_type;

                    using pairing_policy = pairing::pairing_policy<CurveType>;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const verification_key_type &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {

                        return process(uscs_ppzksnark_process_verification_key<CurveType>::process(vk), primary_input,
                                       proof);
                    }

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &pvk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {

                        assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                        const accumulation_vector<typename CurveType::template g1_type<>> accumulated_IC =
                            pvk.encoded_IC_query.accumulate_chunk(primary_input.begin(), primary_input.end(), 0);
                        assert(accumulated_IC.is_fully_accumulated());
                        const typename CurveType::template g1_type<>::value_type &acc = accumulated_IC.first;

                        bool result = true;

                        if (!proof.is_well_formed()) {
                            result = false;
                        }

                        typename pairing_policy::g1_precomputed_type proof_V_g1_with_acc_precomp =
                            precompute_g1<CurveType>(proof.V_g1 + acc);
                        typename pairing_policy::g2_precomputed_type proof_V_g2_precomp =
                            precompute_g2<CurveType>(proof.V_g2);
                        typename CurveType::gt_type::value_type V_1 =
                            miller_loop<CurveType>(proof_V_g1_with_acc_precomp, pvk.pp_G2_one_precomp);
                        typename CurveType::gt_type::value_type V_2 =
                            miller_loop<CurveType>(pvk.pp_G1_one_precomp, proof_V_g2_precomp);
                        typename CurveType::gt_type::value_type V =
                            final_exponentiation<CurveType>(V_1 * V_2.unitary_inversed());

                        if (V != CurveType::gt_type::value_type::one()) {
                            result = false;
                        }

                        typename pairing_policy::g1_precomputed_type proof_H_g1_precomp =
                            precompute_g1<CurveType>(proof.H_g1);
                        typename CurveType::gt_type::value_type SSP_1 =
                            miller_loop<CurveType>(proof_V_g1_with_acc_precomp, proof_V_g2_precomp);
                        typename CurveType::gt_type::value_type SSP_2 =
                            miller_loop<CurveType>(proof_H_g1_precomp, pvk.vk_Z_g2_precomp);
                        typename CurveType::gt_type::value_type SSP = final_exponentiation<CurveType>(
                            SSP_1.unitary_inversed() * SSP_2 * pvk.pairing_of_g1_and_g2);

                        if (SSP != CurveType::gt_type::value_type::one()) {
                            result = false;
                        }

                        typename pairing_policy::g1_precomputed_type proof_V_g1_precomp =
                            precompute_g1<CurveType>(proof.V_g1);
                        typename pairing_policy::g1_precomputed_type proof_alpha_V_g1_precomp =
                            precompute_g1<CurveType>(proof.alpha_V_g1);
                        typename CurveType::gt_type::value_type alpha_V_1 =
                            miller_loop<CurveType>(proof_V_g1_precomp, pvk.vk_alpha_tilde_g2_precomp);
                        typename CurveType::gt_type::value_type alpha_V_2 =
                            miller_loop<CurveType>(proof_alpha_V_g1_precomp, pvk.vk_tilde_g2_precomp);
                        typename CurveType::gt_type::value_type alpha_V =
                            final_exponentiation<CurveType>(alpha_V_1 * alpha_V_2.unitary_inversed());

                        if (alpha_V != CurveType::gt_type::value_type::one()) {
                            result = false;
                        }

                        return result;
                    }
                };

                template<typename CurveType>
                class uscs_ppzksnark_verifier_strong_input_consistency {
                    typedef detail::uscs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const verification_key_type &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return uscs_ppzksnark_verifier_strong_input_consistency<CurveType>::process(
                            uscs_ppzksnark_process_verification_key<CurveType>::process(vk), primary_input, proof);
                    }

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &pvk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {

                        bool result = true;

                        if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                            result = false;
                        } else {
                            result = uscs_ppzksnark_verifier_weak_input_consistency<CurveType>::process(
                                pvk, primary_input, proof);
                        }

                        return result;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP
