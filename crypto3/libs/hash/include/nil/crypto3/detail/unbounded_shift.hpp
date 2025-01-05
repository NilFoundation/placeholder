//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP
#define CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP

#include <boost/assert.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<size_t type_bits, typename T>
            T low_bits(T x, size_t bit_count) {
                if (bit_count == 0)
                    return T();
                if (bit_count == type_bits)
                    return x;
                if (bit_count > type_bits)
                    throw "Not enough bits in the number";
                T lowmask = ~T();
                lowmask >>= type_bits - bit_count;
                return x & lowmask;
            }

            template<size_t type_bits, typename T>
            T high_bits(const T& x, size_t bit_count) {
                if (bit_count == 0)
                    return T();
                if (bit_count == type_bits)
                    return x;
                if (bit_count > type_bits)
                    throw "Not enough bits in the number";

                T highmask = ~T();
                highmask <<= type_bits - bit_count;
                return x & highmask;
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_UNBOUNDED_SHIFT_HPP
