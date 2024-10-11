///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#pragma once

#include <climits>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <type_traits>

// #include <boost/multiprecision/cpp_int/import_export.hpp>  // For 'extract_bits'.
#include <boost/multiprecision/detail/endian.hpp>
#include <boost/multiprecision/traits/std_integer_traits.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {

    namespace detail {
        using limb_type = nil::crypto3::multiprecision::limb_type;

        /* This specialization is used when assigning `chunk_bits`
         * of `bits` into `val` at `bit_location` in case where `val`
         * is larger than one limb (machine word).
         */
        template<unsigned Bits, class Unsigned>
        void assign_bits(big_integer<Bits>& val, Unsigned bits, std::size_t bit_location,
                         std::size_t chunk_bits, const std::integral_constant<bool, false>& tag) {
            unsigned limb = bit_location / (sizeof(limb_type) * CHAR_BIT);
            unsigned shift = bit_location % (sizeof(limb_type) * CHAR_BIT);

            limb_type mask = chunk_bits >= sizeof(limb_type) * CHAR_BIT
                                 ? ~static_cast<limb_type>(0u)
                                 : (static_cast<limb_type>(1u) << chunk_bits) - 1;

            limb_type value = static_cast<limb_type>(bits & mask) << shift;
            if (value) {
                // We are ignoring any bits that will not fit into the number.
                // We are not throwing, we will use as many bits from the input as we need to.
                if (val.size() > limb) {
                    val.limbs()[limb] |= value;
                }
            }

            /* If some extra bits need to be assigned to the next limb */
            if (chunk_bits > sizeof(limb_type) * CHAR_BIT - shift) {
                shift = sizeof(limb_type) * CHAR_BIT - shift;
                chunk_bits -= shift;
                bit_location += shift;
                auto extra_bits = bits >> shift;
                if (extra_bits) {
                    assign_bits(val, extra_bits, bit_location, chunk_bits, tag);
                }
            }
        }

        /* This specialization is used when assigning `chunk_bits`
         * of `bits` into `val` at `bit_location` in case where `val`
         * fits into one limb (machine word).
         */
        template<unsigned Bits, class Unsigned>
        void assign_bits(big_integer<Bits>& val, Unsigned bits, std::size_t bit_location,
                         std::size_t chunk_bits,
                         const std::integral_constant<bool, true>& /*unused*/) {
            using local_limb_type = typename big_integer<Bits>::local_limb_type;
            //
            // Check for possible overflow, this may trigger an exception, or have no effect
            // depending on whether this is a checked integer or not:
            //
            // We are not throwing, we will use as many bits from the input as we need to.
            // BOOST_ASSERT(!((bit_location >= sizeof(local_limb_type) * CHAR_BIT) && bits));

            local_limb_type mask = chunk_bits >= sizeof(local_limb_type) * CHAR_BIT
                                       ? ~static_cast<local_limb_type>(0u)
                                       : (static_cast<local_limb_type>(1u) << chunk_bits) - 1;
            local_limb_type value = (static_cast<local_limb_type>(bits) & mask) << bit_location;
            *val.limbs() |= value;

            //
            // Check for overflow bits:
            //
            bit_location = sizeof(local_limb_type) * CHAR_BIT - bit_location;

            // We are not throwing, we will use as many bits from the input as we need to.
            // BOOST_ASSERT(!((bit_location < sizeof(bits) * CHAR_BIT) && (bits >>=
            // bit_location)));
        }

        template<unsigned Bits, class Iterator>
        big_integer<Bits>& import_bits_generic(big_integer<Bits>& val, Iterator i, Iterator j,
                                               std::size_t chunk_size = 0, bool msv_first = true) {
            big_integer<Bits> newval;

            using value_type = typename std::iterator_traits<Iterator>::value_type;
            using difference_type = typename std::iterator_traits<Iterator>::difference_type;
            using size_type =
                typename ::boost::multiprecision::detail::make_unsigned<difference_type>::type;
            using tag_type = typename big_integer<Bits>::trivial_tag;

            if (!chunk_size) {
                chunk_size = std::numeric_limits<value_type>::digits;
            }

            size_type limbs = std::distance(i, j);
            size_type bits = limbs * chunk_size;

            // We are not throwing, we will use as many bits from the input as we need to.
            // BOOST_ASSERT(bits <= Bits);

            difference_type bit_location = msv_first ? bits - chunk_size : 0;
            difference_type bit_location_change =
                msv_first ? -static_cast<difference_type>(chunk_size) : chunk_size;

            while (i != j) {
                assign_bits(newval, *i, static_cast<std::size_t>(bit_location), chunk_size,
                            tag_type());
                ++i;
                bit_location += bit_location_change;
            }

            // This will remove the upper bits using upper_limb_mask.
            newval.normalize();

            val.backend() = std::move(newval);
            return val;
        }

        template<unsigned Bits, class T>
        inline big_integer<Bits> import_bits_fast(big_integer<Bits>& val, T* i, T* j,
                                                  std::size_t chunk_size = 0) {
            std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
            std::size_t limb_len = byte_len / sizeof(limb_type);
            if (byte_len % sizeof(limb_type)) {
                ++limb_len;
            }

            big_integer<Bits>& result = val.backend();
            BOOST_VERIFY(result.size() > limb_len);

            result.limbs()[result.size() - 1] = 0u;
            std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(limb_type)));

            // This is probably unneeded, but let it stay for now.
            result.normalize();
            return val;
        }
    }  // namespace detail

    template<unsigned Bits, class Iterator>
    inline big_integer<Bits>& import_bits(big_integer<Bits>& val, Iterator i, Iterator j,
                                          std::size_t chunk_size = 0, bool msv_first = true) {
        return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
    }

    template<unsigned Bits, class T>
    inline big_integer<Bits>& import_bits(big_integer<Bits>& val, T* i, T* j,
                                          std::size_t chunk_size = 0, bool msv_first = true) {
#if CRYPTO3_MP_ENDIAN_LITTLE_BYTE
        if (((chunk_size % CHAR_BIT) == 0) && !msv_first && (sizeof(*i) * CHAR_BIT == chunk_size))
            return detail::import_bits_fast(val, i, j, chunk_size);
#endif
        return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
    }

    template<unsigned Bits, class OutputIterator>
    OutputIterator export_bits(const big_integer<Bits>& val, OutputIterator out,
                               std::size_t chunk_size, bool msv_first = true) {
#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 4244)
#endif
        using tag_type = typename big_integer<Bits>::trivial_tag;
        if (!val) {
            *out = 0;
            ++out;
            return out;
        }
        std::size_t bitcount = eval_msb_imp(val.backend()) + 1;

        std::ptrdiff_t bit_location =
            msv_first ? static_cast<std::ptrdiff_t>(bitcount - chunk_size) : 0;
        const std::ptrdiff_t bit_step =
            msv_first ? static_cast<std::ptrdiff_t>(-static_cast<std::ptrdiff_t>(chunk_size))
                      : static_cast<std::ptrdiff_t>(chunk_size);
        while (bit_location % bit_step) {
            ++bit_location;
        }
        do {
            *out = boost::multiprecision::detail::extract_bits(val.backend(), bit_location,
                                                               chunk_size, tag_type());
            ++out;
            bit_location += bit_step;
        } while ((bit_location >= 0) && (bit_location < static_cast<int>(bitcount)));

        return out;
#ifdef BOOST_MSVC
#pragma warning(pop)
#endif
    }
}  // namespace nil::crypto3::multiprecision
