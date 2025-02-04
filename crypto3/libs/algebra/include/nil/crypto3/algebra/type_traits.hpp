//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP
#define CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            using namespace boost::mpl::placeholders;

            BOOST_TTI_HAS_TYPE(iterator)
            BOOST_TTI_HAS_TYPE(const_iterator)

            BOOST_TTI_HAS_TYPE(extension_policy)
            BOOST_TTI_HAS_TYPE(params_type)
            BOOST_TTI_HAS_TYPE(curve_type)
            BOOST_TTI_HAS_TYPE(field_type)
            BOOST_TTI_HAS_TYPE(underlying_type)
            BOOST_TTI_HAS_TYPE(value_type)
            BOOST_TTI_HAS_TYPE(integral_type)
            BOOST_TTI_HAS_TYPE(base_field_type)
            BOOST_TTI_HAS_TYPE(modular_type)
            BOOST_TTI_HAS_TYPE(scalar_field_type)
            BOOST_TTI_HAS_TYPE(gt_type)

            // BOOST_TTI_HAS_TYPE(g1_type) does not work properly on g1_type since it is a template
            template <typename, typename = std::void_t<>>
            struct has_type_g1_type : std::false_type {};
            template <typename T>
            struct has_type_g1_type<T, std::void_t<typename T::template g1_type<>>> : std::true_type {};

            // BOOST_TTI_HAS_TYPE(g2_type) does not work properly on g2_type since it is a template
            template <typename, typename = std::void_t<>>
            struct has_type_g2_type : std::false_type {};
            template <typename T>
            struct has_type_g2_type<T, std::void_t<typename T::template g2_type<>>> : std::true_type {};

            BOOST_TTI_HAS_TYPE(group_type)

            BOOST_TTI_HAS_STATIC_MEMBER_DATA(value_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(modulus_bits)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(base_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(scalar_field_modulus)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(arity)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(p)
            BOOST_TTI_HAS_STATIC_MEMBER_DATA(q)

            BOOST_TTI_HAS_FUNCTION(to_affine)
            BOOST_TTI_HAS_FUNCTION(to_special)
            BOOST_TTI_HAS_FUNCTION(is_special)
            BOOST_TTI_HAS_FUNCTION(sqrt)

            BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(zero)
            BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(one)
            BOOST_TTI_HAS_FUNCTION(is_zero)
            BOOST_TTI_HAS_FUNCTION(is_well_formed)
            BOOST_TTI_HAS_FUNCTION(double_inplace)
            BOOST_TTI_HAS_FUNCTION(mixed_add)

            BOOST_TTI_HAS_FUNCTION(inversed)

            template<typename T>
            struct is_curve {
                static constexpr bool value =
                    has_type_base_field_type<T>::value &&
                    has_type_scalar_field_type<T>::value &&
                    has_type_g1_type<T>::value;
            };

            /** @brief is typename T either g1 or g2 group */
            template<typename T>
            struct is_curve_group {
                static constexpr bool value =
                    has_type_params_type<T>::value &&
                    has_type_curve_type<T, is_curve<_1> >::value &&
                    has_type_field_type<T>::value &&
                    has_type_value_type<T>::value;
            };

            /** @brief is typename T a field */
            template<typename T>
            struct is_field {
                static const bool value =
                    has_type_value_type<T>::value &&
                    has_static_member_data_value_bits<T, const std::size_t>::value &&
                    has_type_integral_type<T>::value &&
                    has_static_member_data_modulus_bits<T, const std::size_t>::value &&
                    has_type_modular_type<T>::value &&
                    has_static_member_data_arity<T, const std::size_t>::value;
                typedef T type;
            };

            /** @brief is typename T an extended field (e.g. Fp2) */
            template<typename T>
            struct is_extended_field {
                static const bool value =
                    is_field<T>::value &&
                    has_type_extension_policy<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_curve_element {
                static const bool value =
                    has_type_field_type<T>::value &&
                    has_type_group_type<T>::value &&
                    has_static_member_function_zero<T, T>::value &&
                    has_static_member_function_one<T, T>::value &&
                    has_function_is_zero<const T, bool>::value &&
                    has_function_is_well_formed<const T, bool>::value &&
                    has_function_double_inplace<T, void>::value
                    ;
            };

            template<typename T>
            struct has_mixed_add {
                static const bool value = has_function_mixed_add<T, void, boost::mpl::vector<T const&>>::value;
            };

            template<typename T>
            struct is_field_element {
                static const bool value =
                    has_type_field_type<T>::value &&
                    has_function_is_zero<const T, bool>::value &&
                    has_function_inversed<const T, T>::value &&
                    has_static_member_function_zero<T, const T&>::value;
            };

            template<typename T>
            struct is_extended_field_element {
                static const bool value =
                    is_field_element<T>::value &&
                    has_type_underlying_type<T>::value
                    ;
            };

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_TYPE_TRAITS_HPP
