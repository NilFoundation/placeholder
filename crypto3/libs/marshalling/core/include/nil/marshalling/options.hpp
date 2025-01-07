//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
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

/// @file
/// Contains definition of all the options used by the @b Marshalling library

#ifndef MARSHALLING_OPTIONS_HPP
#define MARSHALLING_OPTIONS_HPP

#include <tuple>
#include <type_traits>
#include <limits>
#include <cstdint>
#include <cstddef>

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/status_type.hpp>

namespace nil::crypto3 {
    namespace marshalling {

        namespace types {
            // We cannot include integral.hpp, it includes this file. So just declare the class.
            template<typename TFieldBase, typename T, typename... TOptions>
            class integral;
        }

        namespace option {
            // message/field_t common options

            /// @brief options to specify endian.
            /// @tparam TEndian endian_type type. Must be either nil::crypto3::marshalling::endian::big_endian or
            ///     nil::crypto3::marshalling::endian::little_endian.
            /// @headerfile nil/marshalling/options.hpp
            template<typename TEndian>
            struct endian { };

            /// @brief Alias option to endian_type specifying big endian.
            /// @headerfile nil/marshalling/options.hpp
            using big_endian = endian<nil::crypto3::marshalling::endian::big_endian>;

            /// @brief Alias option to endian_type specifying little endian.
            /// @headerfile nil/marshalling/options.hpp
            using little_endian = endian<nil::crypto3::marshalling::endian::little_endian>;

            /// @brief Option that forces usage of embedded uninitialised data area instead
            ///     of dynamic memory allocation.
            /// @details Applicable to fields that represent collection of raw data or other
            ///     fields, such as nil::crypto3::marshalling::types::array_list or nil::crypto3::marshalling::types::string. By
            ///     default, these fields will use
            ///     <a href="http://en.cppreference.com/w/cpp/container/vector">std::vector</a> or
            ///     <a href="http://en.cppreference.com/w/cpp/string/basic_string">std::string</a>
            ///     for their internal data storage. If this option is used, it will force
            ///     such fields to use @ref nil::crypto3::marshalling::container::static_vector or @ref
            ///     nil::crypto3::marshalling::container::static_string with the capacity provided by this option.
            /// @tparam TSize Size of the storage area in number of elements, for strings it does @b NOT include
            ///     the '\0' terminating character.
            /// @headerfile nil/marshalling/options.hpp
            template<std::size_t TSize>
            struct fixed_size_storage { };

            /// @brief Option that modifies the default behaviour of collection fields to
            ///     prepend the serialized data with number of @b elements information.
            /// @details Quite often when collection of fields is serialized it must be
            ///     prepended with one or more bytes indicating number of elements that will
            ///     follow.
            ///     Applicable to fields that represent collection of raw data or other
            ///     fields, such as nil::crypto3::marshalling::types::array_list or nil::crypto3::marshalling::types::string.@n
            ///     For example sequence of raw bytes must be prefixed with 2 bytes stating
            ///     the size of the sequence:
            ///     @code
            ///     using MyFieldBase = nil::crypto3::marshalling::field_type<nil::crypto3::marshalling::option::BigEndian>;
            ///     using MyField =
            ///         nil::crypto3::marshalling::types::array_list<
            ///             MyFieldBase,
            ///             std::uint8_t,
            ///             nil::crypto3::marshalling::option::sequence_size_field_prefix<
            ///                 nil::crypto3::marshalling::types::integral<MyFieldBase, std::uint16_t>
            ///             >
            ///         >;
            ///     @endcode
            /// @tparam TField Type of the field that represents size
            /// @headerfile nil/marshalling/options.hpp
            template<typename TField>
            struct sequence_size_field_prefix { };

            template <typename TTypeBase>
            using size_t_sequence_size_field_prefix = sequence_size_field_prefix<
               nil::crypto3::marshalling::types::integral<TTypeBase, std::size_t>>;

            /// @brief Option that forces usage of fixed size storage for sequences with fixed
            ///     size.
            /// @details Equivalent to @ref fixed_size_storage option, but applicable only
            ///     to sequence types @ref nil::crypto3::marshalling::types::array_list or @ref nil::crypto3::marshalling::types::string,
            ///     that alrady use @ref sequence_fixed_size option. Usage of this option do not require knowledge of
            ///     the storage area size.
            /// @headerfile nil/marshalling/options.hpp
            struct sequence_fixed_size_use_fixed_size_storage { };

        }    // namespace option
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_OPTIONS_HPP
