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

#ifndef NIL_DETAIL_TYPE_TRAITS_HPP
#define NIL_DETAIL_TYPE_TRAITS_HPP

#include <tuple>

#include <boost/tti/tti.hpp>
#include <boost/array.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil::crypto3::marshalling {
    namespace detail {

        /* Traits imported from algebra type_traits.hpp */
        using nil::crypto3::detail::has_iterator;
        using nil::crypto3::detail::has_const_iterator;
        using nil::crypto3::detail::has_begin;
        using nil::crypto3::detail::has_end;

        using nil::crypto3::detail::is_iterator;
        using nil::crypto3::detail::is_range;
        using nil::crypto3::detail::is_container;

        /// @brief Check whether provided type is a variant of
        ///     <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
        /// @tparam TType Type to check.
        template<typename TType>
        struct is_tuple {
            /// @brief By default Value has value false. Will be true for any
            /// variant of <a href="http://en.cppreference.com/w/cpp/utility/tuple">std::tuple</a>.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename... TArgs>
        struct is_tuple<std::tuple<TArgs...>> {
            static const bool value = true;
        };
        /// @endcond

        //----------------------------------------

        /// @brief Check whether TType type is included in the tuple TTuple
        /// @tparam TType Type to check
        /// @tparam TTuple Tuple
        /// @pre @code IsTuple<TTuple>::value == true @endcode
        template<typename TType, typename TTuple>
        class is_in_tuple {
            static_assert(is_tuple<TTuple>::value, "TTuple must be std::tuple");

        public:
            /// @brief By default the value is false, will be set to true if TType
            ///     is found in TTuple.
            static const bool value = false;
        };

        /// @cond SKIP_DOC
        template<typename TType, typename TFirst, typename... TRest>
        class is_in_tuple<TType, std::tuple<TFirst, TRest...>> {
        public:
            static const bool value
                = std::is_same<TType, TFirst>::value || is_in_tuple<TType, std::tuple<TRest...>>::value;
        };

        template<typename TType>
        class is_in_tuple<TType, std::tuple<>> {
        public:
            static const bool value = false;
        };

        template<typename Value>
        struct is_array {
            static const bool value = false;
        };

        template<typename T, size_t ArraySize>
        struct is_array<std::array<T, ArraySize>> {
            static const bool value = true;
        };

        template<typename T, size_t ArraySize>
        struct is_array<boost::array<T, ArraySize>> {
            static const bool value = true;
        };

        /// @endcond
    }    // namespace detail
}    // namespace nil

#endif    // NIL_DETAIL_TYPE_TRAITS_HPP
