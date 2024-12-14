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

#ifndef MARSHALLING_PROCESSING_SIZE_TO_TYPE_HPP
#define MARSHALLING_PROCESSING_SIZE_TO_TYPE_HPP

#include <array>
#include <cstdint>

#include <nil/marshalling/processing/detail/size_to_type.hpp>

namespace nil::crypto3 {
    namespace marshalling {
        namespace processing {
            /// @cond SKIP_DOC

            template<std::size_t TSize, bool TSigned = false>
            class size_to_type {
                using byte_type = typename size_to_type<1, TSigned>::type;

            public:
                using type = std::array<byte_type, TSize>;
            };

            template<std::size_t TSize>
            struct size_to_type<TSize, false> {
                using type = typename detail::size_to_type_helper<TSize>::type;
            };

            template<std::size_t TSize>
            struct size_to_type<TSize, true> {
                using type = typename std::make_signed<typename size_to_type<TSize, false>::type>::type;
            };

            /// @endcond

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_SIZE_TO_TYPE_HPP
