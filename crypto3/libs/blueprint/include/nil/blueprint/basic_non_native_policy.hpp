//---------------------------------------------------------------------------//
// Copyright (c) 2020-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP
#define CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType, typename OperatingFieldType>
            struct basic_non_native_policy_field_type;

            /*
             * Specialization for non-native Ed25519 base field element on Pallas base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::curves::ed25519::base_field_type> {

                constexpr static const std::uint32_t ratio = 4;    // 66,66,66,66 bits
                using non_native_field_type = typename crypto3::algebra::curves::ed25519::base_field_type;
                using native_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<2 * native_field_type::policy_type::modulus_bits>;

                using var = crypto3::zk::snark::plonk_variable<typename native_field_type::value_type>;

                typedef std::array<var, ratio> non_native_var_type;
                typedef std::array<native_field_type::value_type, ratio> chopped_value_type;

                constexpr static const std::array<std::size_t, ratio> chunk_sizes = {66, 66, 66, 66};


                static native_field_type::value_type get_i_th_chunk(non_native_field_type::value_type input,
                                        std::size_t i_th) {
                    assert(i_th < ratio && "non-native type does not have that much chunks!");
                    extended_integral_type result = extended_integral_type(
                        non_native_field_type::integral_type(input.to_integral()));
                    native_field_type::integral_type base = 1;
                    native_field_type::integral_type mask = (base << chunk_sizes[i_th]) - 1;
                    std::size_t shift = 0;
                    for (std::size_t i = 1; i <= i_th; i++) {
                        shift += chunk_sizes[i - 1];
                    }

                    return (result >> shift) & mask;
                }


                static chopped_value_type chop_non_native(non_native_field_type::value_type input) {
                    chopped_value_type result;
                    for (std::size_t i = 0; i < ratio; i++) {
                        result[i] = get_i_th_chunk(input, i);
                    }
                    return result;
                }

                static non_native_field_type::value_type glue_non_native(chopped_value_type input) {
                    non_native_field_type::value_type result;
                    result = non_native_field_type::value_type(
                        native_field_type::integral_type(input[0].to_integral()));
                    for (std::size_t i = 1; i < ratio; i++) {
                        std::size_t shift = 0;
                        for (std::size_t j = 0; j < i; j++) {
                            shift += chunk_sizes[j];
                        }
                        result += non_native_field_type::value_type(
                            native_field_type::integral_type(input[i].to_integral())
                            << shift);
                    }
                    return result;
                }

            };

            /*
             * Specialization for non-native Ed25519 scalar field element on Pallas base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::curves::ed25519::scalar_field_type> {

                constexpr static const std::uint32_t ratio = 1;

                typedef crypto3::zk::snark::plonk_variable<typename crypto3::algebra::curves::pallas::base_field_type::value_type>
                non_native_var_type;
            };

            /*
             * Specialization for non-native Pallas scalar field element on Pallas base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::curves::pallas::scalar_field_type> {

                constexpr static const std::uint32_t ratio = 2;    // 254, 1 bits
                using non_native_field_type = typename crypto3::algebra::curves::pallas::scalar_field_type;
                using native_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<2 * native_field_type::policy_type::modulus_bits>;
                using var = crypto3::zk::snark::plonk_variable<native_field_type>;

                typedef std::array<var, ratio> non_native_var_type;
                typedef std::array<native_field_type::value_type, ratio> chopped_value_type;

                constexpr static const std::array<std::size_t, ratio> chunk_sizes = {254, 1};


                static native_field_type::value_type get_i_th_chunk(non_native_field_type::value_type input,
                                        std::size_t i_th) {
                    assert(i_th < ratio && "non-native type does not have that much chunks!");
                    extended_integral_type result = input.to_integral();
                    native_field_type::integral_type base = 1;
                    native_field_type::integral_type mask = (base << chunk_sizes[i_th]) - 1;
                    std::size_t shift = 0;
                    for (std::size_t i = 1; i <= i_th; i++) {
                        shift += chunk_sizes[i - 1];
                    }

                    return (result >> shift) & mask;
                }


                static chopped_value_type chop_non_native(non_native_field_type::value_type input) {
                    chopped_value_type result;
                    for (std::size_t i = 0; i < ratio; i++) {
                        result[i] = get_i_th_chunk(input, i);
                    }
                    return result;
                }

                static non_native_field_type::value_type glue_non_native(chopped_value_type input) {
                    non_native_field_type::value_type result;
                    result = non_native_field_type::value_type(
                        native_field_type::integral_type(input[0].to_integral()));
                    for (std::size_t i = 1; i < ratio; i++) {
                        std::size_t shift = 0;
                        for (std::size_t j = 0; j < i; j++) {
                            shift += chunk_sizes[j];
                        }
                        result += non_native_field_type::value_type(
                            native_field_type::integral_type(input[i].to_integral())
                            << shift);
                    }
                    return result;
                }

            };

            /*
             * Specialization for non-native bls12381 scalar field element on pallas base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::fields::bls12_scalar_field<381>> {

                constexpr static const std::uint32_t ratio = 1;

                typedef crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>::value_type>
                non_native_var_type;
            };


            /*
             * Specialization for non-native bls12381 scalar field element on bls12381 base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::fields::bls12_base_field<381>,
                                                      typename crypto3::algebra::fields::bls12_scalar_field<381>> {

                constexpr static const std::uint32_t ratio = 1;

                typedef crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>::value_type>
                non_native_var_type;
            };


            /*
             * Specialization for non-native bls12-381 base field element on Pallas base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::curves::pallas::base_field_type,
                                                      typename crypto3::algebra::fields::bls12_base_field<381>> {
                constexpr static const std::uint32_t ratio = 0; // not implemented yet
                using var = crypto3::zk::snark::plonk_variable<typename crypto3::algebra::curves::pallas::base_field_type>;
                typedef std::array<var, ratio> non_native_var_type;
            };

            /*
             * Specialization for non-native Pallas base field element on bls12-381 base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::fields::bls12_base_field<381>,
                                                      typename crypto3::algebra::curves::pallas::base_field_type> {

                constexpr static const std::uint32_t ratio = 0; // not implemented yet
                using var = crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>>;
                typedef std::array<var, ratio> non_native_var_type;
            };

            /*
             * Specialization for non-native Pallas scalar field element on bls12-381 base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::fields::bls12_base_field<381>,
                                                      typename crypto3::algebra::curves::pallas::scalar_field_type> {

                constexpr static const std::uint32_t ratio = 0; // not implemented yet
                using var = crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>>;
                typedef std::array<var, ratio> non_native_var_type;
            };

            /*
             * Specialization for non-native Ed25519 base field element on bls12-381 base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::fields::bls12_base_field<381>,
                                                      typename crypto3::algebra::curves::ed25519::base_field_type> {
                constexpr static const std::uint32_t ratio = 0; // not implemented yet
                using var = crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>>;
                typedef std::array<var, ratio> non_native_var_type;
            };

            /*
             * Specialization for non-native Ed25519 scalar field element on bls12-381 base field
             */
            template<>
            struct basic_non_native_policy_field_type<typename crypto3::algebra::fields::bls12_base_field<381>,
                                                      typename crypto3::algebra::curves::ed25519::scalar_field_type> {
                constexpr static const std::uint32_t ratio = 0; // not implemented yet
                using var = crypto3::zk::snark::plonk_variable<typename crypto3::algebra::fields::bls12_base_field<381>>;
                typedef std::array<var, ratio> non_native_var_type;
            };

            /*
             * Native element type.
             */
            template<typename BlueprintFieldType>
            struct basic_non_native_policy_field_type<BlueprintFieldType, BlueprintFieldType> {

                constexpr static const std::uint32_t ratio = 1;

                typedef crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> value_type;
            };

            /*
             * Big unsigned numbers
            */
            template<typename BlueprintFieldType>
            struct basic_non_native_policy_field_type<BlueprintFieldType,
                    nil::crypto3::multiprecision::big_uint<256>> {

                constexpr static const std::uint32_t ratio = 2; // 128, 128 bits
                // not actually a field, but we preserve the interface
                using non_native_field_type = typename nil::crypto3::multiprecision::big_uint<256>;
                using native_field_type = typename crypto3::algebra::curves::pallas::base_field_type;
                using extended_integral_type = nil::crypto3::multiprecision::big_uint<2 * native_field_type::policy_type::modulus_bits>;
                using var = crypto3::zk::snark::plonk_variable<typename native_field_type::value_type>;

                typedef std::array<var, ratio> non_native_var_type;
                typedef std::array<native_field_type::value_type, ratio> chopped_value_type;

                constexpr static const std::array<std::size_t, ratio> chunk_sizes = {128, 128};


                static native_field_type::value_type get_i_th_chunk(non_native_field_type input,
                                        std::size_t i_th) {
                    assert(i_th < ratio && "non-native type does not have that much chunks!");
                    extended_integral_type result = extended_integral_type(
                        input);

                    native_field_type::integral_type base = 1;
                    native_field_type::integral_type mask = (base << chunk_sizes[i_th]) - 1;
                    std::size_t shift = 0;
                    for (std::size_t i = 1; i <= i_th; i++) {
                        shift += chunk_sizes[i - 1];
                    }

                    return (result >> shift) & mask;
                }


                static chopped_value_type chop_non_native(non_native_field_type input) {
                    chopped_value_type result;
                    for (std::size_t i = 0; i < ratio; i++) {
                        result[i] = get_i_th_chunk(input, i);
                    }
                    return result;
                }

                static non_native_field_type glue_non_native(chopped_value_type input) {
                    non_native_field_type result;
                    result = non_native_field_type(
                        native_field_type::integral_type(input[0].to_integral()));
                    for (std::size_t i = 1; i < ratio; i++) {
                        std::size_t shift = 0;
                        for (std::size_t j = 0; j < i; j++) {
                            shift += chunk_sizes[j];
                        }
                        result += non_native_field_type(
                            native_field_type::integral_type(input[i].to_integral())
                            << shift);
                    }
                    return result;
                }
            };
        }    // namespace detail

        template<typename BlueprintFieldType>
        class basic_non_native_policy;

        template<>
        class basic_non_native_policy<typename crypto3::algebra::curves::pallas::base_field_type> {

            using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

        public:
            template<typename OperatingFieldType>
            using field = typename detail::basic_non_native_policy_field_type<BlueprintFieldType, OperatingFieldType>;
        };

        template<>
        class basic_non_native_policy<typename crypto3::algebra::fields::bls12_base_field<381>> {

            using BlueprintFieldType = typename crypto3::algebra::fields::bls12_base_field<381>;

        public:
            template<typename OperatingFieldType>
            using field = typename detail::basic_non_native_policy_field_type<BlueprintFieldType, OperatingFieldType>;
        };




    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_BASIC_NON_NATIVE_POLICY_HPP
