//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template <typename TTypeBase, typename FieldElementType>
                using field_element_vector_type = nil::crypto3::marshalling::types::standard_array_list<
                    TTypeBase,
                    field_element<TTypeBase, FieldElementType>
                >;

                // ******************* Marshalling of commitment params for Basic Fri and KZG. ********************************* //

                template<typename Endianness, typename IntegerType>
                nil::crypto3::marshalling::types::standard_size_t_array_list<nil::crypto3::marshalling::field_type<Endianness>>
                fill_integer_vector(const std::vector<IntegerType>& integral_vector) {

                    using TTypeBase = nil::crypto3::marshalling::field_type<Endianness>;
                    using integral_type = nil::crypto3::marshalling::types::integral<TTypeBase, IntegerType>;
                    using integral_vector_type = nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>;

                    integral_vector_type result;

                    std::vector<integral_type> &val = result.value();
                    for (std::size_t i = 0; i < integral_vector.size(); i++) {
                        val.push_back(integral_type(integral_vector[i]));
                    }
                    return result;
                }

                template<typename Endianness, typename IntegerType>
                std::vector<IntegerType>
                make_integer_vector(
                    const nil::crypto3::marshalling::types::standard_size_t_array_list<nil::crypto3::marshalling::field_type<Endianness> >& filled_vector)
                {
                    std::vector<IntegerType> result;
                    result.reserve(filled_vector.value().size());
                    for (std::size_t i = 0; i < filled_vector.value().size(); i++) {
                        result.emplace_back(filled_vector.value()[i].value());
                    }
                    return result;
                }

                // C++ does not allow partial specialization of alias templates, so we need to use a helper struct.
                // This struct will also be used for the dummy commitment params used in testing.
                template<typename TTypeBase, typename CommitmentParamsType, typename Enable = void>
                struct commitment_params{
                    using type = nil::crypto3::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
                                nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>,
                                nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>
                            >
                        >;
                };

                // Marshalling function for dummy params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<
                    nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType,
                    std::enable_if_t<!nil::crypto3::zk::is_lpc<CommitmentSchemeType> && !nil::crypto3::zk::is_kzg<CommitmentSchemeType>>
                >::type
                fill_commitment_params(const typename CommitmentSchemeType::params_type &dummy_params) {
                    using TTypeBase = typename nil::crypto3::marshalling::field_type<Endianness>;
                    using result_type = typename commitment_params<TTypeBase, CommitmentSchemeType>::type;

                    return result_type(std::make_tuple(
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(0),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(0)
                    ));
                }

                // Define commitment_params marshalling type for LPC.
                template<typename TTypeBase, typename CommitmentSchemeType>
                struct commitment_params<
                    TTypeBase,
                    CommitmentSchemeType,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>
                > {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using integral_type = nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>;
                    using type =
                        nil::crypto3::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
//                              constexpr static std::size_t lambda;
                                integral_type,
//                              constexpr static std::size_t m;
                                integral_type,
//                              constexpr static std::uint32_t grinding_parameters; If use_grinding==false, this will be 0.
                                integral_type,
//                              const std::size_t max_degree;
                                integral_type,
//                              const std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;
//                              For each evaluation_domain we will include the unity root only.
                                field_element_vector_type<TTypeBase, typename CommitmentParamsType::field_type::value_type>,
//                              const std::vector<std::size_t> step_list;
                                nil::crypto3::marshalling::types::standard_size_t_array_list<TTypeBase>,
//                              const std::size_t expand_factor;
                                integral_type
                            >
                        >;
                };

                // Marshalling function for FRI params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<
                    nil::crypto3::marshalling::field_type<Endianness>,
                    CommitmentSchemeType,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>
                >::type fill_commitment_params(const typename CommitmentSchemeType::params_type &fri_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::crypto3::marshalling::field_type<Endianness>;
                    using FieldType = typename CommitmentParamsType::field_type;
                    using result_type = typename commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType>::type;

                    std::vector<typename FieldType::value_type> D_unity_roots;
                    for (const auto& domain : fri_params.D) {
                        D_unity_roots.push_back(domain->get_unity_root());
                    }

                    return result_type(std::make_tuple(
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.lambda),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.m),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.use_grinding?fri_params.grinding_parameter:0),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.max_degree),
                        fill_field_element_vector<typename FieldType::value_type, Endianness>(D_unity_roots),
                        fill_integer_vector<Endianness>(fri_params.step_list),
                        nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>(fri_params.expand_factor)
                    ));
                }

                template<typename Endianness, typename CommitmentSchemeType>
                typename CommitmentSchemeType::params_type
                make_commitment_params(const typename commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_lpc<CommitmentSchemeType>>>::type &filled_params) {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;

                    std::size_t lambda = std::get<0>(filled_params.value()).value();
                    // We skip value #1 which is 'm'. It's a static value, cannot be set from a marshalling.
                    // We still need to include it when converting to a marshalling structure, to include it
                    // in the transcript value intialization.
                    std::size_t grinding_parameter = std::get<2>(filled_params.value()).value();
                    std::size_t max_degree = std::get<3>(filled_params.value()).value();
                    std::size_t degree_log = std::ceil(std::log2(max_degree));

                    // We skip value #4, which is unity roots. They will be generated again.

                    auto step_list = make_integer_vector<Endianness, std::size_t>(std::get<5>(filled_params.value()));
                    std::size_t expand_factor = std::get<6>(filled_params.value()).value();
                    std::size_t r = std::accumulate(step_list.begin(), step_list.end(), 0);

                    return CommitmentParamsType(
                        step_list,
                        degree_log,
                        lambda,
                        expand_factor,
                        (grinding_parameter != 0),
                        grinding_parameter
                    );
                }

                // Define commitment_params marshalling type for KZG.
                template<typename Endianness, typename CommitmentSchemeType>
                struct commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>> {
                    using CommitmentParamsType = typename CommitmentSchemeType::params_type;
                    using TTypeBase = typename nil::crypto3::marshalling::field_type<Endianness>;

                    using type =
                        nil::crypto3::marshalling::types::bundle<
                            TTypeBase,
                            std::tuple<
//                              std::vector<typename curve_type::template g1_type<>::value_type> commitment_key;
                                nil::crypto3::marshalling::types::standard_array_list<
                                nil::crypto3::marshalling::field_type<Endianness>,
                                curve_element<nil::crypto3::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g1_type<>>
>
                                ,
//                              verification_key_type verification_key;
                                nil::crypto3::marshalling::types::standard_array_list<
                                nil::crypto3::marshalling::field_type<Endianness>,
                                curve_element<nil::crypto3::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g2_type<>>>
                            >
                        >;
                };

                // Marshalling function for KZG params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>>::type
                fill_commitment_params(const typename CommitmentSchemeType::params_type &kzg_params) {
                    using result_type = typename commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType>::type;

                    nil::crypto3::marshalling::types::standard_array_list<
                    nil::crypto3::marshalling::field_type<Endianness>,
                    curve_element<nil::crypto3::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g1_type<>>>
                    filled_commitment = fill_curve_element_vector<typename CommitmentSchemeType::curve_type::template g1_type<>, Endianness>(kzg_params.commitment_key);

                    nil::crypto3::marshalling::types::standard_array_list<
                    nil::crypto3::marshalling::field_type<Endianness>,
                    curve_element<nil::crypto3::marshalling::field_type<Endianness>, typename CommitmentSchemeType::curve_type::template g2_type<>>>
                    filled_verification_key = fill_curve_element_vector<typename CommitmentSchemeType::curve_type::template g2_type<>, Endianness>(kzg_params.verification_key);

                    return result_type(std::make_tuple(
                        filled_commitment,
                        filled_verification_key
                    ));
                }

                // Marshalling function for KZG params.
                template<typename Endianness, typename CommitmentSchemeType>
                typename CommitmentSchemeType::params_type
                make_commitment_params(const typename commitment_params<nil::crypto3::marshalling::field_type<Endianness>, CommitmentSchemeType, std::enable_if_t<nil::crypto3::zk::is_kzg<CommitmentSchemeType>>>::type &filled_kzg_params) {
                    return result_type(std::make_tuple(
                        make_curve_element_vector<typename CommitmentSchemeType::curve_type::template g1_type<>, Endianness>(std::get<0>(filled_kzg_params.value()).value()),
                        make_curve_element_vector<typename CommitmentSchemeType::curve_type::template g2_type<>, Endianness>(std::get<1>(filled_kzg_params.value()).value())
                    ));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_PARAMS_HPP
