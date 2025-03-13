//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

#include <limits>
#include <map>
#include <ratio>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/math/types/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                using batch_info_type = std::map<std::size_t, std::size_t>; // batch_id->batch_size

                ///////////////////////////////////////////////////
                // fri::merkle_proofs marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using merkle_proof_vector_type = nil::crypto3::marshalling::types::standard_array_list<
                    TTypeBase,
                    types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                >;

                template< typename Endianness, typename FRI >
                merkle_proof_vector_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_merkle_proof_vector(const std::vector<typename FRI::merkle_proof_type> &merkle_proofs) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = merkle_proof_vector_type<TTypeBase, FRI>;

                    filled_type filled;


                    for( size_t i = 0; i < merkle_proofs.size(); i++){
                        filled.value().push_back(
                            fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(merkle_proofs[i])
                        );
                    }
                    return filled;
                }

                template<typename Endianness, typename FRI>
                std::vector<typename FRI::merkle_proof_type>
                make_merkle_proof_vector(merkle_proof_vector_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled) {
                    std::vector<typename FRI::merkle_proof_type> merkle_proofs;
                    for( std::size_t i = 0; i < filled.value().size(); i++ ){
                        merkle_proofs.push_back(
                            make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(filled.value()[i])
                        );
                    }
                    return merkle_proofs;
                }

                ///////////////////////////////////////////////////
                // fri::initial_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_initial_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // polynomials_values_type values;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::standard_array_list<
                                    TTypeBase,
                                    field_element<TTypeBase, typename FRI::field_type::value_type>>>
                        >,
                        // merkle_proof_type p;
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_initial_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_fri_initial_proof(
                    const typename FRI::initial_proof_type &initial_proof
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = fri_initial_proof_type<TTypeBase, FRI>;
                    using outer_list_type = nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename FRI::field_type::value_type>
                        >
                    >;
                    using inner_list_type = nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename FRI::field_type::value_type>
                    >;

                    filled_type filled;

                    for (std::size_t i = 0; i < initial_proof.values.size(); i++) {
                        outer_list_type outer_list;
                        for (std::size_t j = 0; j < initial_proof.values[i].size(); j++) {
                            inner_list_type inner_list;
                            for (std::size_t k = 0; k < FRI::m; k++) {
                                inner_list.value().push_back(
                                    field_element<TTypeBase, typename FRI::field_type::value_type>(
                                        initial_proof.values[i][j][k])
                                );
                            }
                            outer_list.value().push_back(inner_list);
                        }
                        std::get<0>(filled.value()).value().push_back(outer_list);
                    }
                    // merkle_proof_type p;
                    std::get<1>(filled.value()) =
                        fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(initial_proof.p);

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::initial_proof_type
                make_fri_initial_proof(
                    const fri_initial_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled
                ) {
                    typename FRI::initial_proof_type initial_proof;
                    // polynomials_values_type values;
                    auto &values = std::get<0>(filled.value()).value();
                    initial_proof.values.resize(values.size());
                    for (std::size_t i = 0; i < values.size(); i++) {
                        auto &outer_values = values[i].value();
                        initial_proof.values[i].resize(outer_values.size());
                        for (std::size_t j = 0; j < outer_values.size(); j++) {
                            auto &inner_values = outer_values[j].value();
                            for (std::size_t k = 0; k < FRI::m; k++) {
                                initial_proof.values[i][j][k] = inner_values[k].value();
                            }
                        }
                    }

                    // merkle_proof_type p;
                    initial_proof.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                        std::get<1>(filled.value()));

                    return initial_proof;
                }

                ///////////////////////////////////////////////////
                // fri::round_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_round_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> y;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename FRI::field_type::value_type>
                        >,
                        // merkle_proof_type p;
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_round_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_fri_round_proof(
                    const typename FRI::round_proof_type &round_proof
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = fri_round_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (std::size_t i = 0; i < round_proof.y.size(); i++) {
                        for (std::size_t j = 0; j < FRI::m; j++) {
                            std::get<0>(filled.value()).value().push_back(
                                field_element<TTypeBase, typename FRI::field_type::value_type>(
                                    round_proof.y[i][j])
                            );
                        }
                    }
                    // merkle_proof_type p;
                    std::get<1>(filled.value()) =
                        fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(round_proof.p);

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::round_proof_type
                make_fri_round_proof(
                    const fri_round_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled
                ) {
                    typename FRI::round_proof_type round_proof;
                    // std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> y;
                    const std::size_t size = std::get<0>(filled.value()).value().size();
                    if (size % FRI::m != 0) {
                        throw std::invalid_argument(
                                std::string("Number of elements should be multiple of m = ") +
                                std::to_string(FRI::m) + " got: " +
                                std::to_string(size));
                    }
                    const std::size_t coset_size = size / FRI::m;
                    std::size_t cur = 0;
                    round_proof.y.resize(coset_size);
                    for (std::size_t i = 0; i < coset_size; i++) {
                        for (std::size_t j = 0; j < FRI::m; j++) {
                            round_proof.y[i][j] = std::get<0>(filled.value()).value()[cur++].value();
                        }
                    }

                    // merkle_proof_type p;
                    round_proof.p = make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                        std::get<1>(filled.value()));

                    return round_proof;
                }

                ///////////////////////////////////////////////////
                // fri::query_proof_type marshalling
                ///////////////////////////////////////////////////
                template<typename TTypeBase, typename FRI>
                using fri_query_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::map<std::size_t, initial_proof_type> initial_proof;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            fri_initial_proof_type<TTypeBase, FRI>
                        >,
                        // std::vector<round_proof_type> round_proofs;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            fri_round_proof_type<TTypeBase, FRI>
                        >
                    >
                >;

                template<typename Endianness, typename FRI>
                fri_query_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_fri_query_proof(
                    const typename FRI::query_proof_type &query_proof
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = fri_query_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (auto &[key, value] : query_proof.initial_proof) {
                        std::get<0>(filled.value()).value().push_back(
                            fill_fri_initial_proof<Endianness, FRI>(value)
                        );
                    }

                    for (std::size_t i = 0; i < query_proof.round_proofs.size(); i++) {
                        std::get<1>(filled.value()).value().push_back(
                            fill_fri_round_proof<Endianness, FRI>(query_proof.round_proofs[i])
                        );
                    }

                    return filled;
                }

                template<typename Endianness, typename FRI>
                typename FRI::query_proof_type
                make_fri_query_proof(
                    const fri_query_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled,
                    const batch_info_type &batch_info,
                    const std::vector<std::uint8_t> &step_list)
                {
                    typename FRI::query_proof_type query_proof;
                    // std::map<std::size_t, initial_proof_type> initial_proof;
                    std::size_t cur = 0;
                    std::size_t coset_size = 1 << (step_list[0] - 1);
                    auto const& initial_proof = std::get<0>(filled.value()).value();
                    for (const auto &[batch_id, batch_size] : batch_info) {
                        if (cur >= initial_proof.size()) {
                            throw std::invalid_argument("Not enough initial_proof values");
                        }
                        query_proof.initial_proof[batch_id] =
                            make_fri_initial_proof<Endianness, FRI>(
                                initial_proof[cur++], batch_size, coset_size
                            );
                    }
                    // std::vector<round_proof_type> round_proofs;
                    cur = 0;
                    auto const& round_proofs = std::get<1>(filled.value()).value();
                    for (std::size_t r = 0; r < step_list.size(); r++) {
                        coset_size = r == step_list.size() - 1 ? 1 : (1 << (step_list[r+1]-1));
                        if (cur >= round_proofs.size()) {
                            throw std::invalid_argument("Not enough round_proofs values");
                        }
                        query_proof.round_proofs.push_back(
                            make_fri_round_proof<Endianness, FRI>(
                                round_proofs[cur++]
                            )
                        );
                    }

                    return query_proof;
                }

                ///////////////////////////////////////////////////
                // fri::proof_type marshalling
                ///////////////////////////////////////////////////
                template <typename TTypeBase, typename FRI> struct fri_proof {
                    using type = nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // step_list.size() merkle roots
                            // Fixed size. It's Ok
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type
                            >,

                            // step_list.
                            // We'll check is it good for current EVM instance
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                            >,

                            // Polynomials' values for initial proofs
                            // Fixed size
                            // lambda * polynomials_num * m
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>
                            >,

                            // Polynomials' values for round proofs
                            // Fixed size
                            // lambda * \sum_rounds{m^{r_i}}
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename FRI::field_type::value_type>
                            >,

                            // Merkle proofs for initial proofs
                            // Fixed size lambda * batches_num
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                            >,

                            // Merkle proofs for round proofs
                            // Fixed size lambda * |step_list|
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                            >,

                            // std::select_container<math::polynomial> final_polynomials
                            // May be different size, because real degree may be less than before. So put int in the end
                            typename polynomial<TTypeBase, typename FRI::polynomial_type>::type,

                            // proof of work.
                            nil::crypto3::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>
                        >
                    >;
                };

                using batch_info_type = std::map<std::size_t, std::size_t>;// batch_id->batch_size

                template <typename Endianness, typename FRI>
                typename fri_proof<nil::crypto3::marshalling::field_type<Endianness>, FRI>::type
                fill_fri_proof(const typename FRI::proof_type &proof, const batch_info_type &batch_info, const typename FRI::params_type& params) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;

                    // merkle roots
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase, typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type
                    > filled_fri_roots;
                    for( size_t i = 0; i < proof.fri_roots.size(); i++){
                        filled_fri_roots.value().push_back(fill_merkle_node_value<typename FRI::commitment_type, Endianness>(proof.fri_roots[i]));
                    }

                    std::size_t lambda = proof.query_proofs.size();
                    // initial_polynomials values
                    std::vector<typename FRI::field_type::value_type> initial_val;
                    for( std::size_t i = 0; i < lambda; i++ ){
                        auto &query_proof = proof.query_proofs[i];
                        for( const auto &it: query_proof.initial_proof){
                            auto &initial_proof = it.second;
                            if (initial_proof.values.size() != batch_info.at(it.first)) {
                                throw std::invalid_argument(
                                        std::string("Initial proof has wrong size. Expected: ") +
                                        std::to_string(initial_proof.values.size()) + " got: " +
                                        std::to_string(batch_info.at(it.first)));
                            }
                            for( std::size_t j = 0; j < initial_proof.values.size(); j++ ){
                                for(std::size_t k = 0; k < initial_proof.values[j].size(); k++ ){
                                    for( std::size_t l = 0; l < FRI::m; l++ ){
                                        initial_val.push_back(initial_proof.values[j][k][l]);
                                    }
                                }
                                if (std::size_t(1 << (params.step_list[0] - 1)) != initial_proof.values[j].size()) {
                                    throw std::invalid_argument(
                                            std::string("Initial proof element has wrong size. Expected: ") +
                                            std::to_string(std::size_t(1 << (params.step_list[0] - 1))) + " got: " +
                                            std::to_string(initial_proof.values[j].size()));
                                }
                            }
                        }
                    }
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename FRI::field_type::value_type>
                    > filled_initial_val = fill_field_element_vector<typename FRI::field_type::value_type, Endianness>(initial_val);

                    // fill round values
                    std::vector<typename FRI::field_type::value_type> round_val;
                    for( std::size_t i = 0; i < lambda; i++ ){
                        auto &query_proof = proof.query_proofs[i];
                        for( std::size_t j = 0; j < query_proof.round_proofs.size(); j++ ){
                            auto &round_proof = query_proof.round_proofs[j];
                            for( std::size_t k = 0; k < round_proof.y.size(); k++){
                                round_val.push_back(round_proof.y[k][0]);
                                round_val.push_back(round_proof.y[k][1]);
                            }
                        }
                    }
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename FRI::field_type::value_type>
                    > filled_round_val = fill_field_element_vector<typename FRI::field_type::value_type, Endianness>(round_val);

                    // step_list
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                    > filled_step_list;
                    for (const auto& step : params.step_list) {
                        filled_step_list.value().push_back(nil::crypto3::marshalling::types::integral<TTypeBase, std::uint8_t>(step));
                    }

                    // initial merkle proofs
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    > filled_initial_merkle_proofs;
                    for( std::size_t i = 0; i < lambda; i++){
                        const auto &query_proof = proof.query_proofs[i];
                        for( const auto &it:query_proof.initial_proof){
                            const auto &initial_proof = it.second;
                            filled_initial_merkle_proofs.value().push_back(
                                fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(initial_proof.p)
                            );
                        }
                    }

                    // round merkle proofs
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        typename types::merkle_proof<TTypeBase, typename FRI::merkle_proof_type>
                    > filled_round_merkle_proofs;
                    for( std::size_t i = 0; i < lambda; i++){
                        const auto &query_proof = proof.query_proofs[i];
                        for( const auto &round_proof:query_proof.round_proofs){
                            filled_round_merkle_proofs.value().push_back(
                                fill_merkle_proof<typename FRI::merkle_proof_type, Endianness>(round_proof.p)
                            );
                        }
                    }

                    auto filled_final_polynomial = fill_polynomial<Endianness, typename FRI::polynomial_type>(
                        proof.final_polynomial
                    );

                    return typename fri_proof<nil::crypto3::marshalling::field_type<Endianness>, FRI>::type(
                        std::tuple(
                            filled_fri_roots, filled_step_list, filled_initial_val, filled_round_val,
                            filled_initial_merkle_proofs, filled_round_merkle_proofs, filled_final_polynomial,
                            nil::crypto3::marshalling::types::integral<TTypeBase, typename FRI::grinding_type::output_type>(
                                proof.proof_of_work)
                        )
                    );
                }

                template <typename Endianness, typename FRI>
                typename FRI::proof_type
                make_fri_proof(
                    const typename fri_proof<nil::crypto3::marshalling::field_type<Endianness>, FRI>::type &filled_proof,
                    const batch_info_type &batch_info)
                {
                    typename FRI::proof_type proof;
                    // merkle roots
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); i++) {
                        proof.fri_roots.push_back(
                            make_merkle_node_value<typename FRI::commitment_type, Endianness>(std::get<0>(filled_proof.value()).value()[i])
                        );
                    }
                    // step_list
                    std::vector<std::uint8_t> step_list;
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); i++) {
                        auto c = std::get<1>(filled_proof.value()).value()[i].value();
                        step_list.push_back(c);
                    }

                    std::size_t lambda = std::get<5>(filled_proof.value()).value().size() / step_list.size();
                    proof.query_proofs.resize(lambda);
                    // initial_polynomials values
                    std::size_t coset_size = 1 << (step_list[0] - 1);
                    std::size_t cur = 0;
                    for (std::size_t i = 0; i < lambda; i++) {
                        for (const auto &it: batch_info) {
                            proof.query_proofs[i].initial_proof[it.first] = typename FRI::initial_proof_type();
                            proof.query_proofs[i].initial_proof[it.first].values.resize(it.second);
                            for (std::size_t j = 0; j < it.second; j++) {
                                proof.query_proofs[i].initial_proof[it.first].values[j].resize(coset_size);
                                for (std::size_t k = 0; k < coset_size; k++) {
                                    for (std::size_t l = 0; l < FRI::m; l++, cur++ ) {
                                        if (cur >= std::get<2>(filled_proof.value()).value().size()) {
                                            throw std::invalid_argument(
                                                std::string("Too few elements provided for initial_polynomials values: ") +
                                                std::to_string(std::get<2>(filled_proof.value()).value().size()));
                                        }
                                        proof.query_proofs[i].initial_proof[it.first].values[j][k][l] =
                                            std::get<2>(filled_proof.value()).value()[cur].value();
                                    }
                                }
                            }
                        }
                    }

                    // round polynomials values
                    cur = 0;
                    for (std::size_t i = 0; i < lambda; i++) {
                        proof.query_proofs[i].round_proofs.resize(step_list.size());
                        for (std::size_t r = 0; r < step_list.size(); r++ ) {
                            coset_size = r == step_list.size() - 1? 1: (1 << (step_list[r+1]-1));
                            proof.query_proofs[i].round_proofs[r].y.resize(coset_size);
                            for (std::size_t j = 0; j < coset_size; j++) {
                                for (std::size_t k = 0; k < FRI::m; k++, cur++) {
                                    if (cur >= std::get<3>(filled_proof.value()).value().size()) {
                                        throw std::invalid_argument(
                                            std::string("Too few elements provided for round polynomials values: ") +
                                            std::to_string(std::get<3>(filled_proof.value()).value().size()));
                                    }
                                    proof.query_proofs[i].round_proofs[r].y[j][k] = std::get<3>(filled_proof.value()).value()[cur].value();
                                }
                            }
                        }
                    }
                    // initial merkle proofs
                    auto const& initial_merkle_proofs = std::get<4>(filled_proof.value()).value();
                    cur = 0;
                    for (std::size_t i = 0; i < lambda; i++) {
                        for (const auto &it: batch_info) {
                            if (cur >= initial_merkle_proofs.size()) {
                                throw std::invalid_argument("Not enough initial_merkle_proof values");
                            }
                            proof.query_proofs[i].initial_proof[it.first].p =
                                make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                                    std::get<4>(filled_proof.value()).value()[cur++]
                            );
                        }
                    }

                    // round merkle proofs
                    auto const& round_merkle_proofs = std::get<5>(filled_proof.value()).value();
                    cur = 0;
                    for (std::size_t i = 0; i < lambda; i++ ) {
                        for (std::size_t r = 0; r < step_list.size(); r++, cur++ ) {
                            if (cur >= round_merkle_proofs.size()) {
                                throw std::invalid_argument("Not enough round_merkle_proof values");
                            }
                            proof.query_proofs[i].round_proofs[r].p =
                                make_merkle_proof<typename FRI::merkle_proof_type, Endianness>(
                                    round_merkle_proofs[cur]
                            );
                        }
                    }

                    // final_polynomial
                    proof.final_polynomial = make_polynomial<Endianness, typename FRI::polynomial_type>(
                        std::get<6>(filled_proof.value())
                    );

                    // proof_of_work
                    proof.proof_of_work = std::get<7>(filled_proof.value()).value();
                    return proof;
                }

                template <typename TTypeBase, typename FRI>
                using initial_proofs_batch_type = nil::crypto3::marshalling::types::standard_array_list<
                    TTypeBase,
                    nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                            >,
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                fri_initial_proof_type<TTypeBase, FRI>
                            >
                        >
                    >
                >;

                template <typename Endianness, typename FRI>
                initial_proofs_batch_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_initial_proofs_batch(const typename FRI::initial_proofs_batch_type &initial_proofs_batch) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = initial_proofs_batch_type<TTypeBase, FRI>;
                    using bundle_type = nil::crypto3::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                            >,
                            nil::crypto3::marshalling::types::standard_array_list<
                                TTypeBase,
                                fri_initial_proof_type<TTypeBase, FRI>
                            >
                        >
                    >;

                    filled_type filled;

                    for (const auto &inital_proof : initial_proofs_batch.initial_proofs) {
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>
                        > filled_step_list;
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            fri_initial_proof_type<TTypeBase, FRI>
                        > filled_initial_proofs;
                        for (const auto &[step_list, proof] : inital_proof) {
                            filled_step_list.value().push_back(
                                nil::crypto3::marshalling::types::integral<TTypeBase, uint8_t>(step_list));
                            filled_initial_proofs.value().push_back(fill_fri_initial_proof<Endianness, FRI>(
                                proof));
                        }
                        auto filled_bundle = std::make_tuple(filled_step_list, filled_initial_proofs);
                        filled.value().push_back(bundle_type(filled_bundle));
                    }

                    return filled;
                }

                template <typename Endianness, typename FRI>
                typename FRI::initial_proofs_batch_type make_initial_proofs_batch(
                    const initial_proofs_batch_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled)
                {
                    typename FRI::initial_proofs_batch_type initial_proofs_batch;
                    for (const auto &batch : filled.value()) {
                        std::map<std::size_t, typename FRI::initial_proof_type> batch_initial_proofs;
                        auto &batch_index_vector = std::get<0>(batch.value()).value();
                        auto &batch_proof_vector = std::get<1>(batch.value()).value();
                        for (std::size_t i = 0; i < batch_index_vector.size(); i++) {
                            batch_initial_proofs[batch_index_vector[i].value()] =
                                make_fri_initial_proof<Endianness, FRI>(batch_proof_vector[i]);
                        }
                        initial_proofs_batch.initial_proofs.push_back(batch_initial_proofs);
                    }
                    return initial_proofs_batch;
                }

                template <typename TTypeBase, typename FRI>
                using round_proofs_batch_type = nil::crypto3::marshalling::types::standard_array_list<
                    TTypeBase,
                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        fri_round_proof_type<TTypeBase, FRI>
                    >
                >;

                template <typename Endianness, typename FRI>
                round_proofs_batch_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_round_proofs_batch(const typename FRI::round_proofs_batch_type &round_proofs_batch) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = round_proofs_batch_type<TTypeBase, FRI>;

                    filled_type filled;

                    for (const auto &round_proof_vector : round_proofs_batch.round_proofs) {
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            fri_round_proof_type<TTypeBase, FRI>
                        > filled_round_proof_vector;
                        for (const auto &round_proof : round_proof_vector) {
                            filled_round_proof_vector.value().push_back(
                                fill_fri_round_proof<Endianness, FRI>(round_proof));
                        }
                        filled.value().push_back(filled_round_proof_vector);
                    }

                    return filled;
                }

                template <typename Endianness, typename FRI>
                typename FRI::round_proofs_batch_type make_round_proofs_batch(
                    const round_proofs_batch_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled)
                {
                    typename FRI::round_proofs_batch_type round_proofs_batch;
                    for (const auto &round_proof_vector : filled.value()) {
                        std::vector<typename FRI::round_proof_type> round_proofs;
                        for (const auto &round_proof : round_proof_vector.value()) {
                            round_proofs.push_back(make_fri_round_proof<Endianness, FRI>(round_proof));
                        }
                        round_proofs_batch.round_proofs.push_back(round_proofs);
                    }
                    return round_proofs_batch;
                }

                template <typename TTypeBase, typename FRI>
                using commitments_part_of_proof_type = nil::crypto3::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        nil::crypto3::marshalling::types::standard_array_list<
                            TTypeBase,
                            typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type
                        >,
                        typename polynomial<TTypeBase, typename FRI::polynomial_type>::type
                    >
                >;

                template <typename Endianness, typename FRI>
                commitments_part_of_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI>
                fill_commitments_part_of_proof(
                    const typename FRI::commitments_part_of_proof &commitments_part_of_proof
                ) {
                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using filled_type = commitments_part_of_proof_type<TTypeBase, FRI>;

                    filled_type filled;

                    nil::crypto3::marshalling::types::standard_array_list<
                        TTypeBase,
                        typename types::merkle_node_value<TTypeBase, typename FRI::merkle_proof_type>::type
                    > filled_fri_roots;
                    for (const auto &fri_root : commitments_part_of_proof.fri_roots) {
                        filled_fri_roots.value().push_back(
                            fill_merkle_node_value<typename FRI::commitment_type, Endianness>(fri_root));
                    }
                    std::get<0>(filled.value()) = filled_fri_roots;

                    std::get<1>(filled.value()) = fill_polynomial<Endianness, typename FRI::polynomial_type>(
                        commitments_part_of_proof.final_polynomial
                    );

                    return filled;
                }

                template <typename Endianness, typename FRI>
                typename FRI::commitments_part_of_proof make_commitments_part_of_proof(
                    const commitments_part_of_proof_type<nil::crypto3::marshalling::field_type<Endianness>, FRI> &filled
                ) {
                    typename FRI::commitments_part_of_proof commitments_part_of_proof;
                    for (const auto &fri_root : std::get<0>(filled.value()).value()) {
                        commitments_part_of_proof.fri_roots.push_back(
                            make_merkle_node_value<typename FRI::commitment_type, Endianness>(fri_root)
                        );
                    }
                    commitments_part_of_proof.final_polynomial =
                        make_polynomial<Endianness, typename FRI::polynomial_type>(
                            std::get<1>(filled.value())
                        );
                    return commitments_part_of_proof;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
