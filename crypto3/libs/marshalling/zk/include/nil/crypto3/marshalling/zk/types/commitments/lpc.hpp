//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

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
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_tree.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/commitment_params.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/polys_evaluator.hpp>

#include <boost/outcome.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // Default commitment type

                // * LPCScheme is like lpc_commitment_scheme
                template <typename TTypeBase, typename LPCScheme>
                struct commitment<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>> {
                    using type = typename merkle_node_value<TTypeBase, typename LPCScheme::commitment_type>::type;
                };

                template <typename Endianness, typename LPCScheme>
                typename commitment<
                    nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type
                fill_commitment(typename LPCScheme::commitment_type commitment) {
                    return fill_merkle_node_value<typename LPCScheme::commitment_type, Endianness>( commitment );
                }

                template <typename Endianness, typename LPCScheme>
                typename LPCScheme::commitment_type
                make_commitment(typename commitment<
                    nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type const& filled_commitment) {
                    return make_merkle_node_value<typename LPCScheme::commitment_type, Endianness>( filled_commitment );
                }

                // * LPCScheme is like lpc_commitment_scheme
                template <typename TTypeBase, typename LPCScheme>
                struct commitment_preprocessed_data<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>> {
                    using type = nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename LPCScheme::field_type::value_type>
                            >
                        >
                    >;
                };

                template <typename Endianness, typename LPCScheme>
                typename commitment_preprocessed_data<
                    nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type
                fill_commitment_preprocessed_data(const typename LPCScheme::preprocessed_data_type& lpc_data){
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using field_marshalling_type = field_element<TTypeBase, typename LPCScheme::field_type::value_type>;

                    using result_type = typename commitment_preprocessed_data<
                        nil::crypto3::marshalling::field_type<Endianness>, LPCScheme
                    >::type;
                    nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase> filled_map_ids;
                    nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase> filled_sizes;
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename LPCScheme::field_type::value_type>
                    > filled_values;

                    for (const auto&[k, v]: lpc_data) {
                        filled_map_ids.value().push_back(nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(k));
                        filled_sizes.value().push_back(nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(v.size()));
                        for (std::size_t i = 0; i < v.size(); i++) {
                            filled_values.value().push_back(field_marshalling_type((v[i])));
                        }
                    }

                    return result_type(
                        std::make_tuple(
                            filled_map_ids,
                            filled_sizes,
                            filled_values
                        )
                    );
                }

                template <typename Endianness, typename LPCScheme>
                typename LPCScheme::preprocessed_data_type
                make_commitment_preprocessed_data(typename commitment_preprocessed_data<
                        nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                        std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                    >::type const& filled_commitment_preprocessed_data
                ) {
                    typename LPCScheme::preprocessed_data_type result;
                    auto const& vector_map    = std::get<0>(filled_commitment_preprocessed_data.value()).value();
                    auto const& vector_sizes  = std::get<1>(filled_commitment_preprocessed_data.value()).value();
                    auto const& vector_values = std::get<2>(filled_commitment_preprocessed_data.value()).value();
                    if (vector_map.size() != vector_sizes.size()) {
                        throw std::invalid_argument("Map size does not equal vector sizes");
                    }
                    std::size_t total_size = 0;
                    for(auto const& size: vector_sizes) {
                        total_size += size.value();
                    }
                    if (vector_values.size() != total_size) {
                        throw std::invalid_argument("Map size does not equal vector sizes");
                    }

                    for (std::size_t i = 0; i < vector_map.size(); i++) {
                        std::size_t k = vector_map[i].value();
                        std::size_t size = vector_sizes[i].value();
                        std::vector<typename LPCScheme::field_type::value_type> v;
                        v.reserve(size);
                        for (std::size_t j = 0; j < size; j++){
                            v.emplace_back(vector_values[i*size + j].value());
                        }
                        result[k] = v;
                    }

                    return result;
                }

                // FOR LPC only because of basic_fri field
                template <typename TTypeBase, typename LPCScheme>
                struct eval_proof<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>> > {
                    using type = nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // Evaluation points storage z
                            eval_storage<TTypeBase, typename LPCScheme::eval_storage_type>,

                            // One fri proof
                            typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type
                        >
                    >;
                };

                template<typename Endianness, typename LPCScheme>
                typename eval_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>>::type
                fill_eval_proof( const typename LPCScheme::proof_type &proof, const typename LPCScheme::fri_type::params_type& fri_params){
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info = proof.z.get_batch_info();

                    auto filled_z = fill_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(proof.z);

                    typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type filled_fri_proof = fill_fri_proof<Endianness, typename LPCScheme::basic_fri>(
                        proof.fri_proof, batch_info, fri_params
                    );

                    return typename eval_proof<TTypeBase, LPCScheme>::type(
                        std::tuple( filled_z, filled_fri_proof)
                    );
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::proof_type make_eval_proof(
                    const typename eval_proof<
                        nil::crypto3::marshalling::field_type<Endianness>,
                        LPCScheme,
                        std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                    >::type &filled_proof
                ) {
                    typename LPCScheme::proof_type proof;

                    proof.z = make_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(
                        std::get<0>(filled_proof.value()));

                    auto batch_info = proof.z.get_batch_info();
                    proof.fri_proof = make_fri_proof<Endianness, typename LPCScheme::basic_fri>(
                        std::get<1>(filled_proof.value()), batch_info);

                    return proof;
                }

                template <typename TTypeBase, typename LPCScheme, typename Enable = void>
                struct precommitment_type;

                // Will be used to store precommitment type of a commitment scheme. It's useful only for LPC for now,
                // and in practive precommitment contains a merkle tree. The following check checks that statement,
                // that the precommitment is a merkle tree.
                template <typename TTypeBase, typename LPCScheme>
                struct precommitment_type<TTypeBase, LPCScheme,
                        std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme> &&
                                         std::is_same<
                                             typename LPCScheme::precommitment_type,
                                             nil::crypto3::containers::merkle_tree<
                                                 typename LPCScheme::precommitment_type::hash_type,
                                                 LPCScheme::precommitment_type::arity
                                             >
                                          >::value>> {
                    using type = merkle_tree<TTypeBase, typename LPCScheme::precommitment_type>;
                };

                template <typename TTypeBase, typename CommitmentScheme, typename enable = void>
                struct commitment_scheme_state;

                // We need the ability to save the whole state of a commitment scheme, every sinlge field,
                // so we can resume our program's execution from where it was stopped.
                // This will allow us to separate the preprocessor from prover, because LPC has a preprocess step, which
                // changes the state of the 'lpc_commitment_scheme' class.
                template <typename TTypeBase, typename LPCScheme>
                struct commitment_scheme_state<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>> > {
                    using type = nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::map<std::size_t, precommitment_type> _trees;
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            nil::crypto3::marshalling::types::standard_array_list<
                                    TTypeBase,
                                    typename precommitment_type<TTypeBase, LPCScheme>::type
                                >,
                            // typename fri_type::params_type _fri_params;
                            typename commitment_params<TTypeBase, LPCScheme>::type,

                            // value_type _etha;
                            field_element<TTypeBase, typename LPCScheme::value_type>,

                            //std::map<std::size_t, bool> _batch_fixed;
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            // Next value was supposed to be a vector of bool, but our marshalling core
                            // does not allow us to create an array_list of bools.
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            // preprocessed_data_type _fixed_polys_values;
                            typename commitment_preprocessed_data<
                                TTypeBase, LPCScheme,
                                std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                            >::type,
                            // std::map<std::size_t, std::vector<typename polynomial_dfs_type::polynomial_type>> _polys_coefficients
                            nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                polynomial_vector<TTypeBase, typename LPCScheme::polynomial_type::polynomial_type>
                            >,
                            // LPC derives from polys_evaluator, so we need to marshall that as well.
                            polys_evaluator<TTypeBase, typename LPCScheme::polys_evaluator_type>
                        >
                    >;
                };

                template<typename Endianness, typename LPCScheme>
                typename commitment_scheme_state<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                                                 std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>>::type
                fill_commitment_scheme(const LPCScheme &scheme) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>;
                    // Yes, on the next line we need "::polynomial_type" twice, the first one intentionally returns poly_dfs.
                    using polynomial_type = typename LPCScheme::polynomial_type::polynomial_type;
                    using polynomial_vector_marshalling_type = polynomial_vector<TTypeBase, polynomial_type>;
                    using result_type = typename commitment_scheme_state<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>::type;

                    // std::map<std::size_t, precommitment_type> _trees;
                    nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase> filled_trees_keys;
                    nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            typename precommitment_type<TTypeBase, LPCScheme>::type> filled_trees_values;
                    for (const auto&[key, value]: scheme.get_trees()) {
                        filled_trees_keys.value().push_back(nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(key));
                        // Precommitment for LPC is a merkle tree. We may want to abstract away this part into a separate
                        // fill_precommitment function.
                        filled_trees_values.value().push_back(
                            fill_merkle_tree<typename LPCScheme::precommitment_type, Endianness>(value));
                    }

                    //std::map<std::size_t, bool> _batch_fixed;
                    nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase> filled_batch_fixed_keys;
                    nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase> filled_batch_fixed_values;
                    for (const auto&[key, value]: scheme.get_batch_fixed()) {
                        filled_batch_fixed_keys.value().push_back(
                            nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(key));
                        // Here we convert the value, that is a 'bool' into size_t, which is not good.
                        filled_batch_fixed_values.value().push_back(
                            nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(value));
                    }

                    // std::map<std::size_t, std::vector<typename polynomial_dfs_type::polynomial_type>> _polys_coefficients
                    auto [filled_polys_keys, filled_polys_values] = fill_std_map<
                            TTypeBase,
                            size_t_marshalling_type,
                            polynomial_vector_marshalling_type,
                            std::size_t,
                            std::vector<polynomial_type>>(
                        scheme.get_polys_coefficients(), fill_size_t<TTypeBase>, fill_polynomial_vector<Endianness, polynomial_type>);

                    return result_type(std::make_tuple(
                        filled_trees_keys,
                        filled_trees_values,
                        fill_commitment_params<Endianness, LPCScheme>(scheme.get_fri_params()),
                        field_element<TTypeBase, typename LPCScheme::value_type>(scheme.get_etha()),
                        filled_batch_fixed_keys,
                        filled_batch_fixed_values,
                        fill_commitment_preprocessed_data<Endianness, LPCScheme>(scheme.get_fixed_polys_values()),
                        filled_polys_keys,
                        filled_polys_values,
                        fill_polys_evaluator<Endianness, typename LPCScheme::polys_evaluator_type>(
                            static_cast<typename LPCScheme::polys_evaluator_type>(scheme))
                    ));
                }

                template<typename Endianness, typename LPCScheme>
                outcome::result<LPCScheme, nil::crypto3::marshalling::status_type>
                make_commitment_scheme(
                    typename commitment_scheme_state<
                        nil::crypto3::marshalling::field_type<Endianness>, LPCScheme,
                        std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>>::type& filled_commitment_scheme
                ) {
                    using nil::crypto3::marshalling::types::make_size_t;
                    using nil::crypto3::marshalling::types::make_std_map;

                    // Yes, on the next line we need "::polynomial_type" twice, the first one intentionally returns poly_dfs.
                    using polynomial_type = typename LPCScheme::polynomial_type::polynomial_type;

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using value_type = typename polynomial_type::value_type;

                    using size_t_marshalling_type = nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>;
                    using polynomial_vector_marshalling_type = polynomial_vector<TTypeBase, polynomial_type>;

                    std::map<std::size_t, typename LPCScheme::precommitment_type> trees;
                    const auto& filled_tree_keys = std::get<0>(filled_commitment_scheme.value()).value();
                    const auto& filled_tree_values = std::get<1>(filled_commitment_scheme.value()).value();

                    if (filled_tree_keys.size() != filled_tree_values.size()) {
                        return nil::crypto3::marshalling::status_type::invalid_msg_data;
                    }

                    for (std::size_t i = 0; i < filled_tree_keys.size(); i++) {
                        trees[std::size_t(filled_tree_keys[i].value())] =
                            make_merkle_tree<typename LPCScheme::precommitment_type, Endianness>(
                                filled_tree_values[i]);
                    }

                    typename LPCScheme::fri_type::params_type fri_params = make_commitment_params<Endianness, LPCScheme>(
                        std::get<2>(filled_commitment_scheme.value()));
                    typename LPCScheme::value_type etha = std::get<3>(filled_commitment_scheme.value()).value();

                    std::map<std::size_t, bool> batch_fixed;
                    const auto& batch_fixed_keys = std::get<4>(filled_commitment_scheme.value()).value();
                    const auto& batch_fixed_values = std::get<5>(filled_commitment_scheme.value()).value();
                    if (batch_fixed_keys.size() != batch_fixed_values.size()) {
                        return nil::crypto3::marshalling::status_type::invalid_msg_data;
                    }

                    for (std::size_t i = 0; i < batch_fixed_keys.size(); i++) {
                        // Here we convert the value from type size_t back into a 'bool', which is not good.
                        batch_fixed[std::size_t(batch_fixed_keys[i].value())] = bool(batch_fixed_values[i].value());
                    }

                    typename LPCScheme::preprocessed_data_type fixed_polys_values =
                        make_commitment_preprocessed_data<Endianness, LPCScheme>(
                            std::get<6>(filled_commitment_scheme.value()));

                    auto polys_coefficients = make_std_map<
                        TTypeBase, std::size_t, std::vector<polynomial_type>,
                        size_t_marshalling_type, polynomial_vector_marshalling_type>(
                            std::get<7>(filled_commitment_scheme.value()),
                            std::get<8>(filled_commitment_scheme.value()),
                            make_size_t<TTypeBase>,
                            make_polynomial_vector<Endianness, polynomial_type>);

                    typename LPCScheme::polys_evaluator_type evaluator = make_polys_evaluator<
                            Endianness, typename LPCScheme::polys_evaluator_type>(
                        std::get<9>(filled_commitment_scheme.value())
                        );

                    return LPCScheme(evaluator, trees, fri_params, etha, batch_fixed, fixed_polys_values, polys_coefficients);
                }

                template <typename TTypeBase, typename LPCScheme>
                using initial_fri_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // typename basic_fri::round_proofs_batch_type fri_round_proof;
                        nil::crypto3::marshalling::types::round_proofs_batch_type<
                            TTypeBase,
                            typename LPCScheme::basic_fri>,
                        // typename basic_fri::commitments_part_of_proof fri_commitments_proof_part;
                        nil::crypto3::marshalling::types::commitments_part_of_proof_type<
                            TTypeBase,
                            typename LPCScheme::basic_fri>
                    >
                >;

                template <typename Endianness, typename LPCScheme>
                initial_fri_proof_type<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>
                fill_fri_round_proof(const typename LPCScheme::fri_proof_type &proof) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::round_proofs_batch_type<
                        TTypeBase,
                        typename LPCScheme::basic_fri> filled_round_proofs_batch;
                    nil::crypto3::marshalling::types::commitments_part_of_proof_type<
                        TTypeBase,
                        typename LPCScheme::basic_fri> filled_commitments_part_of_proof;

                    filled_round_proofs_batch = fill_round_proofs_batch<Endianness, typename LPCScheme::basic_fri>(
                        proof.fri_round_proof);

                    filled_commitments_part_of_proof =
                        fill_commitments_part_of_proof<Endianness, typename LPCScheme::basic_fri>(
                            proof.fri_commitments_proof_part);

                    return initial_fri_proof_type<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>(
                        std::make_tuple(filled_round_proofs_batch, filled_commitments_part_of_proof));
                }

                template <typename Endianness, typename LPCScheme>
                typename LPCScheme::fri_proof_type
                make_initial_fri_proof(
                    const initial_fri_proof_type<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme> &filled_proof)
                {
                    typename LPCScheme::fri_proof_type proof;

                    proof.fri_round_proof = make_round_proofs_batch<
                        Endianness, typename LPCScheme::basic_fri>(
                            std::get<0>(filled_proof.value()));

                    proof.fri_commitments_proof_part = make_commitments_part_of_proof<
                        Endianness, typename LPCScheme::basic_fri>(
                            std::get<1>(filled_proof.value()));

                    return proof;
                }

                template<typename TTypeBase, typename LPCScheme>
                using inital_eval_proof = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // eval_storage_type z;
                        eval_storage<TTypeBase, typename LPCScheme::eval_storage_type>,
                        // typename basic_fri::initial_proofs_batch_type initial_fri_proofs;
                        initial_proofs_batch_type<TTypeBase, typename LPCScheme::basic_fri>
                    >
                >;

                template<typename Endianness, typename LPCScheme>
                inital_eval_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>
                fill_initial_eval_proof(
                    const typename LPCScheme::lpc_proof_type &intial_proof
                ){
                    auto filled_z = fill_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(
                        intial_proof.z);

                    initial_proofs_batch_type<
                        nil::crypto3::marshalling::field_type<Endianness>, typename LPCScheme::basic_fri> filled_fri_proof =
                            fill_initial_proofs_batch<Endianness, typename LPCScheme::basic_fri>(
                                intial_proof.initial_fri_proofs
                            );

                    return inital_eval_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>(
                        std::tuple(filled_z, filled_fri_proof)
                    );
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::lpc_proof_type
                make_initial_eval_proof(
                    const inital_eval_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme> &filled_proof)
                {
                    typename LPCScheme::lpc_proof_type proof;

                    proof.z = make_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(
                        std::get<0>(filled_proof.value()));

                    proof.initial_fri_proofs = make_initial_proofs_batch<Endianness, typename LPCScheme::basic_fri>(
                        std::get<1>(filled_proof.value()));

                    return proof;
                }

                template<typename TTypeBase, typename LPCScheme>
                using aggregated_proof = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // fri_proof_type fri_proof;
                        initial_fri_proof_type<TTypeBase, LPCScheme>,
                        // std::vector<lpc_proof_type> initial_proofs_per_prover;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            inital_eval_proof<TTypeBase, LPCScheme>
                        >,
                        // typename LPCParams::grinding_type::output_type proof_of_work;
                        nil::crypto3::marshalling::types::integral<
                            TTypeBase, typename LPCScheme::params_type::grinding_type::output_type>
                    >
                >;

                template<typename Endianness, typename LPCScheme>
                aggregated_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>
                fill_aggregated_proof(
                    const typename LPCScheme::aggregated_proof_type &proof
                ){
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    initial_fri_proof_type<TTypeBase, LPCScheme> filled_fri_proof =
                        fill_fri_round_proof<Endianness, LPCScheme>(
                            proof.fri_proof
                        );

                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        inital_eval_proof<TTypeBase, LPCScheme>
                    > filled_initial_proofs;
                    for (const auto &initial_proof : proof.initial_proofs_per_prover) {
                        filled_initial_proofs.value().push_back(
                            fill_initial_eval_proof<Endianness, LPCScheme>(
                                initial_proof
                            )
                        );
                    }

                    return aggregated_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme>(
                        std::make_tuple(
                            filled_fri_proof,
                            filled_initial_proofs,
                            nil::crypto3::marshalling::types::integral<
                                TTypeBase, typename LPCScheme::params_type::grinding_type::output_type>(
                                    proof.proof_of_work)
                        )
                    );
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::aggregated_proof_type
                make_aggregated_proof(
                    const aggregated_proof<nil::crypto3::marshalling::field_type<Endianness>, LPCScheme> &filled_proof
                ) {
                    typename LPCScheme::aggregated_proof_type proof;

                    proof.fri_proof = make_initial_fri_proof<Endianness, LPCScheme>(
                        std::get<0>(filled_proof.value()));

                    for (const auto &filled_initial_proof : std::get<1>(filled_proof.value()).value()) {
                        proof.initial_proofs_per_prover.push_back(
                            make_initial_eval_proof<Endianness, LPCScheme>(
                                filled_initial_proof
                            )
                        );
                    }

                    proof.proof_of_work = std::get<2>(filled_proof.value()).value();

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
