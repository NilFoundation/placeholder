//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef MARSHALLING_TYPE_TRAITS_HPP
#define MARSHALLING_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/marshalling/detail/field_base.hpp>

#include <nil/marshalling/types/tag.hpp>

namespace nil::crypto3 {
    namespace marshalling {
        BOOST_TTI_HAS_TYPE(tag)

        /// @brief Compile time check function of whether a provided type is any
        ///     variant of nil::crypto3::marshalling::types::array_list.
        /// @tparam T Any type.
        /// @return true in case provided type is any variant of @ref array_list
        /// @related nil::crypto3::marshalling::types::array_list
        template<typename T>
        struct is_array_list {

            static const bool value = has_type_tag<T, 
                boost::is_same<boost::mpl::placeholders::_1, types::tag::array_list>>::value;
        };

        template<typename T>
        struct is_raw_array_list {
            static const bool value = has_type_tag<T, 
                boost::is_same<boost::mpl::placeholders::_1, types::tag::raw_array_list>>::value;
        };

        /// @brief Compile time check function of whether a provided type is any
        ///     variant of nil::crypto3::marshalling::types::bundle.
        /// @tparam T Any type.
        /// @return true in case provided type is any variant of @ref bundle
        /// @related nil::crypto3::marshalling::types::bundle
        template<typename T>
        struct is_bundle {
            static const bool value = has_type_tag<T, 
                boost::is_same<boost::mpl::placeholders::_1, types::tag::bundle>>::value;
        };

        /// @brief Compile time check function of whether a provided type is any
        ///     variant of nil::crypto3::marshalling::types::integral.
        /// @tparam T Any type.
        /// @return true in case provided type is any variant of @ref integral
        /// @related nil::crypto3::marshalling::types::integral
        template<typename T>
        struct is_integral {
            static const bool value = has_type_tag<T, 
                boost::is_same<boost::mpl::placeholders::_1, types::tag::integral>>::value;
        };

        /// @brief Compile time check function of whether a provided type is any
        ///     variant of nil::crypto3::marshalling::types::string.
        /// @tparam T Any type.
        /// @return true in case provided type is any variant of @ref string
        /// @related nil::crypto3::marshalling::types::string
        template<typename T>
        struct is_string {
            static const bool value = has_type_tag<T, 
                boost::is_same<boost::mpl::placeholders::_1, types::tag::string>>::value;
        };

        template<typename T>
        struct is_marshalling_type {
            static const bool value = 
                boost::is_base_of<detail::field_base<>, T>::value;
        };

        template<typename T, typename Enabled = void>
        struct is_container;

        template<typename T>
        struct is_container <T, typename std::enable_if<nil::crypto3::marshalling::is_integral<T>::value>::type> {
            static const bool value = false;
        };

        template<typename T>
        struct is_container <T, typename std::enable_if<is_array_list<T>::value
                                                || is_bundle<T>::value>::type> {
            static const bool value = true;
        };

        template<typename T, typename Enabled = void>
        struct is_supported_representation_type {
            static const bool value = false;
        };

        template<typename T>
        struct is_supported_representation_type<T,  typename std::enable_if<std::is_same<std::uint8_t, T>::value
                || std::is_same<std::int8_t, T>::value
                || std::is_same<char, T>::value || std::is_same<bool, T>::value>::type> {
            static const bool value = true;
        };

        template<typename T>
        struct is_supported_representation_type<T,  typename std::enable_if<is_supported_representation_type<typename T::value_type>::value>::type> {
            static const bool value = true;
        };


        // The following four functions we need only because of absence of BOOST_TTI_HAS_MEMBER_FUNCTION for std::string
        template<typename T>
        class has_member_function_clear {
            struct no { };

        protected:
            template<typename C>
            static auto test(std::nullptr_t) -> decltype(std::declval<C>().clear());

            template<typename>
            static no test(...);

        public:
            constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
        };

        template<typename T>
        class has_member_function_reserve {
            struct no { };

        protected:
            template<typename C>
            static auto test(std::nullptr_t) -> decltype(std::declval<C>().reserve(0U));

            template<typename>
            static no test(...);

        public:
            constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
        };

        template<typename T>
        class has_member_function_resize {
            struct no { };

        protected:
            template<typename C>
            static auto test(std::nullptr_t) -> decltype(std::declval<C>().resize(0U));

            template<typename>
            static no test(...);

        public:
            constexpr static const bool value = !std::is_same<no, decltype(test<T>(nullptr))>::value;
        };

        template<typename T>
        class has_member_function_remove_suffix {
        protected:
            typedef char Yes;
            typedef unsigned no;

            template<typename U, U>
            struct ReallyHas;

            template<typename C>
            static Yes test(ReallyHas<void (C::*)(typename C::size_type), &C::remove_suffix> *);

            template<typename>
            static no test(...);

        public:
            constexpr static const bool value = (sizeof(test<T>(nullptr)) == sizeof(Yes));
        };

    }        // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_TYPE_TRAITS_HPP
