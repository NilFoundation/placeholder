//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>
#include <type_traits>

#include <nil/actor/detail/type_traits.hpp>

namespace nil::actor::detail {

    /// Non-cryptographic hash function named after Glenn Fowler, Landon Curt Noll,
    /// and Kiem-Phong Vo.
    ///
    /// See:
    /// - https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    /// - http://www.isthe.com/chongo/tech/comp/fnv/index.html
    BOOST_SYMBOL_VISIBLE size_t fnv_hash(const unsigned char *first, const unsigned char *last);

    BOOST_SYMBOL_VISIBLE size_t fnv_hash_append(size_t intermediate, const unsigned char *first,
                                                const unsigned char *last);

    template<class T>
    enable_if_t<has_data_member<T>::value, size_t> fnv_hash(const T &x) {
        auto ptr = x.data();
        auto first = reinterpret_cast<const uint8_t *>(ptr);
        auto last = first + (sizeof(decay_t<decltype(*ptr)>) * x.size());
        return fnv_hash(first, last);
    }

    template<class T>
    enable_if_t<has_data_member<T>::value, size_t> fnv_hash_append(size_t intermediate, const T &x) {
        auto ptr = x.data();
        auto first = reinterpret_cast<const uint8_t *>(ptr);
        auto last = first + (sizeof(decay_t<decltype(*ptr)>) * x.size());
        return fnv_hash_append(intermediate, first, last);
    }

    template<class T>
    enable_if_t<std::is_integral<T>::value, size_t> fnv_hash(const T &x) {
        auto first = reinterpret_cast<const uint8_t *>(&x);
        return fnv_hash(first, first + sizeof(T));
    }

    template<class T>
    enable_if_t<std::is_integral<T>::value, size_t> fnv_hash_append(size_t interim, const T &x) {
        auto first = reinterpret_cast<const uint8_t *>(&x);
        return fnv_hash_append(interim, first, first + sizeof(T));
    }

}    // namespace nil::actor::detail