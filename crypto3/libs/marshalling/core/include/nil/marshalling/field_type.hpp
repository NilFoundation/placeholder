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
/// @brief Contains definition of @ref nil::crypto3::marshalling::field_type class.

#ifndef MARSHALLING_FIELD_TYPE_HPP
#define MARSHALLING_FIELD_TYPE_HPP

#include <nil/marshalling/processing/access.hpp>
#include <nil/marshalling/detail/field_base.hpp>

namespace nil::crypto3 {
    namespace marshalling {

        /// @brief Base class to all the field classes.
        /// @details Every custom "field" class should inherit from this one.
        /// @tparam TOptions Zero or more options. The supported options are:
        ///     @li nil::crypto3::marshalling::option::big_endian or nil::crypto3::marshalling::option::little_endian - Option to
        ///         specify serialization endian. If none is provided big endian is
        ///         assumed.
        /// @headerfile nil/marshalling/field_type.hpp
        template<typename... TOptions>
        class field_type : public detail::field_base<TOptions...> {
            using base_impl_type = detail::field_base<TOptions...>;

        public:
            /// @brief endian_type type
            /// @details Equal to either @ref nil::crypto3::marshalling::endian::big_endian or
            ///     @ref nil::crypto3::marshalling::endian::little_endian
            using endian_type = typename base_impl_type::endian_type;

            /// @brief Default validity check
            /// @details Always returns true, can be overriden by the derived class
            /// @return Always @b true
            static constexpr bool valid() {
                return true;
            }

            /// @brief Default refresh functionality
            /// @details Does nothing and returns false, can be overriden by the
            ///     derived class
            /// @return Always @b false
            static constexpr bool refresh() {
                return false;
            }

        protected:
            /// @brief Write data into the output buffer.
            /// @details Use this function to write data to the the buffer
            ///          maintained by the caller. The endianness of the data will be
            ///          as specified in the options provided to the class.
            /// @tparam T Type of the value to write. Must be integral.
            /// @tparam Type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static void write_data(T value, TIter &iter) {
                write_data<sizeof(T), T>(value, iter);
            }

            /// @brief Write partial data into the output buffer.
            /// @details Use this function to write partial data to the buffer maintained
            ///          by the caller. The endianness of the data will be as specified
            ///          the class options.
            /// @tparam TSize length of the value in bytes known in compile time.
            /// @tparam T Type of the value to write. Must be integral.
            /// @tparam TIter Type of output iterator
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct buffers, unsafe otherwise.
            template<std::size_t TSize, typename T, typename TIter>
            static void write_data(T value, TIter &iter) {
                static_assert(TSize <= sizeof(T), "Cannot put more bytes than type contains");
                return processing::write_data<TSize, T>(value, iter, endian_type());
            }

            /// @brief Read data from input buffer.
            /// @details Use this function to read data from the intput buffer maintained
            ///     by the caller. The endianness of the data will be as specified in
            ///     options of the class.
            /// @tparam T Return type
            /// @tparam TIter Type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, typename TIter>
            static T read_data(TIter &iter) {
                return read_data<T, sizeof(T)>(iter);
            }

            /// @brief Read partial data from input buffer.
            /// @details Use this function to read data from the intput buffer maintained
            ///     by the caller. The endianness of the data will be as specified in
            ///     options of the class.
            /// @tparam T Return type
            /// @tparam TSize number of bytes to read
            /// @tparam TIter Type of input iterator
            /// @param[in, out] iter Input iterator.
            /// @return The integral type value.
            /// @pre TSize <= sizeof(T)
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The internal pointer of the stream buffer is advanced.
            /// @note Thread safety: Safe for distinct stream buffers, unsafe otherwise.
            template<typename T, std::size_t TSize, typename TIter>
            static T read_data(TIter &iter) {
                static_assert(TSize <= sizeof(T), "Cannot get more bytes than type contains");
                return processing::read_data<T, TSize>(iter, endian_type());
            }
        };

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIELD_TYPE_HPP
