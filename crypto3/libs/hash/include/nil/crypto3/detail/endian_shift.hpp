//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_ENDIAN_SHIFT_HPP
#define CRYPTO3_DETAIL_ENDIAN_SHIFT_HPP

#include <boost/assert.hpp>

#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<typename Endianness, std::size_t WordBits>
            struct endian_shift;

            template<int UnitBits, std::size_t WordBits>
            struct endian_shift<stream_endian::big_unit_big_bit<UnitBits>, WordBits>
                : public basic_functions<WordBits> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                typedef typename basic_functions<WordBits>::word_type word_type;

                // Shift to most significant bits according to endianness
                static word_type &to_msb(word_type &w, std::size_t shift) {
                    w <<= shift;
                    return w;
                }
            };

            template<int UnitBits, std::size_t WordBits>
            struct endian_shift<stream_endian::little_unit_big_bit<UnitBits>, WordBits>
                : public basic_functions<WordBits> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                typedef typename basic_functions<WordBits>::word_type word_type;

                // Shift towards the most significant bits according to endianness
                static word_type &to_msb(word_type &w, std::size_t shift) {
                    if (shift == 0)
                        return w;
                    if (shift == word_bits) {
                        w = 0;
                        return w;
                    }
                    std::size_t shift_rem = shift % UnitBits;
                    std::size_t shift_unit_bits = shift - shift_rem;

                    // First shift by 'shift_rem' bits, the rest is just normal shifts in the opposite direction.
                    std::size_t sz[2] = {UnitBits - shift_rem, shift_rem};
                    word_type masks[2];
                    masks[0] = low_bits<word_bits>(~word_type(), sz[0]) << shift_unit_bits;
                    
                    // We are not going to use masks[1], if "shift_unit_bits + UnitBits == word_bits".
                    if (shift_unit_bits + UnitBits != word_bits) {
                        masks[1] = high_bits<word_bits>(~word_type(), sz[1]) << 
                            (shift_unit_bits + UnitBits);
                    }
                    std::size_t bits_left = word_bits - shift;

                    word_type w_combined = 0;
                    int ind = 0;

                    while (bits_left) {
                        w_combined |= (!ind ? ((w & masks[0]) << shift_rem) :
                                              ((w & masks[1]) >> (UnitBits + sz[0])));
                        bits_left -= sz[ind];
                        masks[ind] <<= UnitBits;
                        ind = 1 - ind;
                    }

                    // Now 'w_combined' is w (the part of w that we are interested in), but shifted by 'shift_rem' bits.
                    // Shift by 'shift_unit_bits' bits in the opposite direction.
                    w = w_combined >> shift_unit_bits;

                    return w;
                }
            };

            template<int UnitBits, std::size_t WordBits>
            struct endian_shift<stream_endian::big_unit_little_bit<UnitBits>, WordBits>
                : public basic_functions<WordBits> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                typedef typename basic_functions<WordBits>::word_type word_type;

                // Shift to most significant bits according to endianness
                static word_type &to_msb(word_type &w, std::size_t shift) {
                    if (shift == 0)
                        return w;
                    if (shift == word_bits) {
                        w = 0;
                        return w;
                    }

                    std::size_t shift_rem = shift % UnitBits;
                    std::size_t shift_unit_bits = shift - shift_rem;

                    // First shift by 'shift_rem' bits, the rest is just normal shifts in the opposite direction.
                    std::size_t sz[2] = {UnitBits - shift_rem, shift_rem};
                    word_type masks[2];
                    masks[0] = high_bits<word_bits, word_type>(~word_type(), sz[0]) >> shift_unit_bits;

                    // We are not going to use masks[1], if "shift_unit_bits + UnitBits == word_bits".
                    if (shift_unit_bits + UnitBits != word_bits) {
                        masks[1] = low_bits<word_bits, word_type>(~word_type(), sz[1]) >> (shift_unit_bits + UnitBits);
                    }

                    std::size_t bits_left = word_bits - shift;
                    word_type w_combined = 0;
                    int ind = 0;

                    while (bits_left) {
                        w_combined |= (!ind ? (w & masks[0] >> shift_rem) :
                                              (w & masks[1] << (UnitBits + sz[0])));
                        bits_left -= sz[ind];
                        masks[ind] >>= UnitBits;
                        ind = 1 - ind;
                    }

                    // Now 'w_combined' is w (the part of w that we are interested in), but shifted by 'shift_rem' bits.
                    // Shift by 'shift_unit_bits' bits in the opposite direction.
                    w = w_combined << shift_unit_bits;

                    return w;
                }
            };

            template<int UnitBits, std::size_t WordBits>
            struct endian_shift<stream_endian::little_unit_little_bit<UnitBits>, WordBits>
                : public basic_functions<WordBits> {

                constexpr static const std::size_t word_bits = basic_functions<WordBits>::word_bits;
                typedef typename basic_functions<WordBits>::word_type word_type;

                // Shift to most significant bits according to endianness
                static word_type &to_msb(word_type &w, std::size_t shift) {
                    w >>= shift;
                    return w;
                }
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_ENDIAN_SHIFT_HPP
