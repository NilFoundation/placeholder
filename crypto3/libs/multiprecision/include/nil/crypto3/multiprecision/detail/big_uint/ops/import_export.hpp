///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
///////////////////////////////////////////////////////////////

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/endian.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<std::size_t Bits, typename Unsigned>
        void assign_bits(big_uint<Bits>& val, Unsigned bits, std::size_t bit_location,
                         std::size_t chunk_bits) {
            std::size_t limb = bit_location / limb_bits;
            std::size_t shift = bit_location % limb_bits;

            limb_type mask = chunk_bits >= limb_bits
                                 ? ~static_cast<limb_type>(0u)
                                 : (static_cast<limb_type>(1u) << chunk_bits) - 1;

            limb_type value = static_cast<limb_type>(bits & mask) << shift;
            if (value) {
                if (limb >= val.limb_count()) {
                    throw std::overflow_error("import_bits: overflow");
                }
                val.limbs()[limb] |= value;
            }

            /* If some extra bits need to be assigned to the next limb */
            if (chunk_bits > limb_bits - shift) {
                shift = limb_bits - shift;
                chunk_bits -= shift;
                bit_location += shift;
                auto extra_bits = bits >> shift;
                if (extra_bits) {
                    assign_bits(val, extra_bits, bit_location, chunk_bits);
                }
            }
        }

        template<std::size_t Bits>
        std::uintmax_t extract_bits(const big_uint<Bits>& val, std::size_t location,
                                    std::size_t count) {
            std::size_t limb = location / limb_bits;
            std::size_t shift = location % limb_bits;
            std::uintmax_t result = 0;
            std::uintmax_t mask = count == std::numeric_limits<std::uintmax_t>::digits
                                      ? ~static_cast<std::uintmax_t>(0)
                                      : (static_cast<std::uintmax_t>(1u) << count) - 1;
            if (count > (limb_bits - shift)) {
                result = extract_bits(val, location + limb_bits - shift, count - limb_bits + shift);
                result <<= limb_bits - shift;
            }
            if (limb < val.limb_count()) {
                result |= (val.limbs()[limb] >> shift) & mask;
            }
            return result;
        }

        template<std::size_t Bits, typename Iterator>
        big_uint<Bits>& import_bits_generic(big_uint<Bits>& result, Iterator i, Iterator j,
                                            std::size_t chunk_size = 0, bool msv_first = true) {
            big_uint<Bits> newval;

            using value_type = typename std::iterator_traits<Iterator>::value_type;
            using difference_type = typename std::iterator_traits<Iterator>::difference_type;
            using size_type = typename std::make_unsigned<difference_type>::type;

            if (!chunk_size) {
                chunk_size = std::numeric_limits<value_type>::digits;
            }

            size_type limbs = std::distance(i, j);
            size_type bits = limbs * chunk_size;

            difference_type bit_location = msv_first ? bits - chunk_size : 0;
            difference_type bit_location_change =
                msv_first ? -static_cast<difference_type>(chunk_size) : chunk_size;

            while (i != j) {
                assign_bits(newval, *i, static_cast<std::size_t>(bit_location), chunk_size);
                ++i;
                bit_location += bit_location_change;
            }

            if (newval.normalize()) {
                throw std::overflow_error("import_bits: overflow");
            }

            result = newval;
            return result;
        }

        template<std::size_t Bits, typename T>
        inline big_uint<Bits>& import_bits_fast(big_uint<Bits>& result, T* i, T* j) {
            std::size_t byte_len = (j - i) * sizeof(*i);
            std::size_t limb_len = byte_len / sizeof(limb_type);
            if (byte_len % sizeof(limb_type)) {
                ++limb_len;
            }

            std::size_t copy_len = (std::min)(byte_len, result.limb_count() * sizeof(limb_type));

            if (std::any_of(reinterpret_cast<const char*>(i), reinterpret_cast<const char*>(j),
                            [](char c) { return c != 0; })) {
                throw std::overflow_error("import_bits: overflow");
            }

            std::memcpy(result.limbs(), i, copy_len);
            std::memset(result.limbs() + copy_len, 0,
                        result.limb_count() * sizeof(limb_type) - copy_len);

            if (result.normalize()) {
                throw std::overflow_error("import_bits: overflow");
            }

            return result;
        }
    }  // namespace detail

    template<std::size_t Bits, typename Iterator,
             std::enable_if_t<!std::is_pointer_v<Iterator>, int> = 0>
    inline big_uint<Bits>& import_bits(big_uint<Bits>& val, Iterator i, Iterator j,
                                       std::size_t chunk_size = 0, bool msv_first = true) {
        return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
    }

    template<std::size_t Bits, typename T>
    inline big_uint<Bits>& import_bits(big_uint<Bits>& val, T* i, T* j, std::size_t chunk_size = 0,
                                       bool msv_first = true) {
#if NIL_CO3_MP_ENDIAN_LITTLE_BYTE
        if (((chunk_size % CHAR_BIT) == 0) && !msv_first && (sizeof(*i) * CHAR_BIT == chunk_size)) {
            return detail::import_bits_fast(val, i, j);
        }
#endif
        return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
    }

    template<std::size_t Bits, typename OutputIterator>
    OutputIterator export_bits(const big_uint<Bits>& val, OutputIterator out,
                               std::size_t chunk_size, bool msv_first = true) {
        if (!val) {
            *out = 0;
            ++out;
            return out;
        }
        std::size_t bitcount = msb(val) + 1;

        std::ptrdiff_t bit_location =
            msv_first ? static_cast<std::ptrdiff_t>(bitcount - chunk_size) : 0;
        const std::ptrdiff_t bit_step = msv_first ? (-static_cast<std::ptrdiff_t>(chunk_size))
                                                  : static_cast<std::ptrdiff_t>(chunk_size);
        while (bit_location % bit_step) {
            ++bit_location;
        }
        do {
            *out = detail::extract_bits(val, bit_location, chunk_size);
            ++out;
            bit_location += bit_step;
        } while ((bit_location >= 0) && (bit_location < static_cast<std::ptrdiff_t>(bitcount)));

        return out;
    }
}  // namespace nil::crypto3::multiprecision
