//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_PLACEHOLDER_PROOF_HPP
#define CRYPTO3_MARSHALLING_PLACEHOLDER_PROOF_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename Proof>
                using placeholder_partial_evaluation_proof = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // batch size integers
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                        >,
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            typename commitment<TTypeBase, typename Proof::commitment_scheme_type>::type
                        >
                    >
                >;

                template<typename Endianness, typename Proof>
                placeholder_partial_evaluation_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof>
                    fill_placeholder_partial_evaluation_proof(
                        const typename Proof::partial_proof_type &partial_proof) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    // batch size integers
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                    > filled_batch_size;
                    // batch commitments
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        typename commitment<TTypeBase, typename Proof::commitment_scheme_type>::type
                    > filled_commitments;
                    for (const auto &[batch_index, commitment] : partial_proof.commitments) {
                        filled_batch_size.value().push_back(
                            nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>(batch_index));
                        filled_commitments.value().push_back(
                            fill_commitment<Endianness, typename Proof::commitment_scheme_type>(commitment));
                    }

                    return placeholder_partial_evaluation_proof<TTypeBase, Proof>(std::make_tuple(
                        filled_batch_size,
                        filled_commitments
                    ));
                }

                template<typename Endianness, typename Proof>
                typename Proof::partial_proof_type make_placeholder_partial_evaluation_proof(
                    const placeholder_partial_evaluation_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof> &filled_proof)
                {
                    typename Proof::partial_proof_type partial_proof;

                    // batch size integers
                    auto filled_batch_size = std::get<0>(filled_proof.value()).value();
                    auto filled_commitments = std::get<1>(filled_proof.value()).value();

                    for (std::size_t i = 0; i < filled_batch_size.size(); i++) {
                        partial_proof.commitments[filled_batch_size[i].value()] =
                            make_commitment<Endianness, typename Proof::commitment_scheme_type>(
                                filled_commitments[i]);
                    }

                    return partial_proof;
                }

                // This should be different for different commitment schemes!
                template<typename TTypeBase, typename Proof>
                using placeholder_evaluation_proof = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        //typename Proof::commitment_scheme_type::eval_proof;
                        typename eval_proof<TTypeBase, typename Proof::commitment_scheme_type>::type
                    >
                >;


                template<typename Endianness, typename Proof, typename CommitmentParamsType>
                placeholder_evaluation_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof>
                    fill_placeholder_evaluation_proof(const typename Proof::evaluation_proof &proof, const CommitmentParamsType& commitment_params) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    using field_marshalling_type = field_element<TTypeBase, typename Proof::field_type::value_type>;

                    // typename commitment_scheme_type::proof_type eval_proof;
                    auto filled_eval_proof =
                        fill_eval_proof<Endianness, typename Proof::commitment_scheme_type>(proof.eval_proof, commitment_params);

                    return placeholder_evaluation_proof<TTypeBase, Proof>(std::make_tuple(
                        filled_eval_proof
                    ));
                }

                template<typename Endianness, typename Proof>
                typename Proof::evaluation_proof make_placeholder_evaluation_proof(
                    const placeholder_evaluation_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof> &filled_proof)
                {
                    typename Proof::evaluation_proof proof;

                    // typename commitment_scheme_type::proof_type combined_value
                    proof.eval_proof = make_eval_proof<Endianness, typename Proof::commitment_scheme_type>(
                        std::get<0>(filled_proof.value()));

                    return proof;
                }

                template<typename TTypeBase, typename Proof>
                using placeholder_proof = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // typename commitment_scheme_type::commitment_type commitments
                        // All of them are similar size. So no nil::crypto3::marshalling::option needed
                        // There won't be too many commitments. So uint8_t is enough for length
                        nil::crypto3::marshalling::types::array_list<
                            TTypeBase,
                            typename commitment<TTypeBase, typename Proof::commitment_scheme_type>::type,
                            nil::crypto3::marshalling::option::sequence_size_field_prefix<nil::crypto3::marshalling::types::integral<TTypeBase, std::uint8_t>>
                        >,

                        // evaluation_proof eval_proof
                        placeholder_evaluation_proof<TTypeBase, Proof>
                    >
                >;

                template<typename Endianness, typename Proof, typename CommitmentParamsType>
                placeholder_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof>
                    fill_placeholder_proof(const Proof &proof, const CommitmentParamsType& commitment_params) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::array_list<
                        TTypeBase,
                        typename commitment<TTypeBase, typename Proof::commitment_scheme_type>::type,
                        nil::crypto3::marshalling::option::sequence_size_field_prefix<nil::crypto3::marshalling::types::integral<TTypeBase, std::uint8_t>>
                    > filled_commitments;
                    for( const auto &it:proof.commitments){
                        filled_commitments.value().push_back(
                            fill_commitment<Endianness, typename Proof::commitment_scheme_type>(it.second)
                        );
                    }

                    return placeholder_proof<TTypeBase, Proof>(std::make_tuple(
                        filled_commitments,
                        fill_placeholder_evaluation_proof<Endianness, Proof>(proof.eval_proof, commitment_params)
                    ));
                }

                template<typename Endianness, typename Proof>
                Proof make_placeholder_proof(
                    const placeholder_proof<nil::crypto3::marshalling::field_type<Endianness>, Proof> &filled_proof)
                {
                    Proof proof;

                    // evaluation_proof eval_proof
                    proof.eval_proof =
                        make_placeholder_evaluation_proof<Endianness, Proof>(std::get<1>(filled_proof.value()));

                    auto batch_info = proof.eval_proof.eval_proof.z.get_batch_info();
                    auto const& commitments = std::get<0>(filled_proof.value()).value();

                    std::size_t cur = 0;
                    for (const auto &it: batch_info ) {
                        if (it.first == Proof::FIXED_VALUES_BATCH) continue;

                        if (cur >= commitments.size()) {
                            throw std::invalid_argument("Not enough values for commitments");
                        }

                        proof.commitments[it.first] = make_commitment<Endianness, typename Proof::commitment_scheme_type>(
                            commitments[cur++]
                        );
                    }

                    return proof;
                }

                template<typename TTypeBase, typename Proof>
                using placeholder_aggregated_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            placeholder_partial_evaluation_proof<TTypeBase, Proof>
                        >,
                        nil::crypto3::marshalling::types::aggregated_proof<TTypeBase, typename Proof::commitment_scheme_type>
                    >
                >;

                template<typename Endianness, typename AggregatedProof, typename Proof>
                placeholder_aggregated_proof_type<nil::crypto3::marshalling::field_type<Endianness>, Proof>
                    fill_placeholder_aggregated_proof(
                        const AggregatedProof &proof
                    ) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        placeholder_partial_evaluation_proof<TTypeBase, Proof>
                    > filled_partial_proofs;
                    for (const auto &it:proof.partial_proofs) {
                        filled_partial_proofs.value().push_back(
                            fill_placeholder_partial_evaluation_proof<Endianness, Proof>(it)
                        );
                    }

                    return placeholder_aggregated_proof_type<TTypeBase, Proof>(std::make_tuple(
                        filled_partial_proofs,
                        fill_aggregated_proof<Endianness, typename Proof::commitment_scheme_type>(
                            proof.aggregated_proof)
                    ));
                }

                template<typename Endianness, typename AggregatedProof, typename Proof>
                AggregatedProof make_placeholder_aggregated_proof(
                    const placeholder_aggregated_proof_type<nil::crypto3::marshalling::field_type<Endianness>, Proof> &filled_proof)
                {
                    AggregatedProof proof;

                    // std::vector<placeholder_partial_proof<FieldType, ParamsType>> partial_proofs;
                    auto filled_partial_proofs = std::get<0>(filled_proof.value()).value();
                    for (const auto &it: filled_partial_proofs) {
                        proof.partial_proofs.push_back(
                            make_placeholder_partial_evaluation_proof<Endianness, Proof>(it)
                        );
                    }

                    // typename commitment_scheme_type::aggregated_proof_type aggregated_proof;
                    proof.aggregated_proof = make_aggregated_proof<
                        Endianness, typename AggregatedProof::commitment_scheme_type>(
                            std::get<1>(filled_proof.value())
                    );

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PLACEHOLDER_PROOF_HPP
