//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>

#include <nil/actor/config.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            template<class T>
            bool cas_weak(std::atomic<T> *obj, T *expected, T desired) {
#if (defined(BOOST_COMP_CLANG_AVAILABLE) && ACTOR_COMPILER_VERSION < 30401) || \
    (defined(BOOST_COMP_GNUC_AVAILABLE) && ACTOR_COMPILER_VERSION < 40803)
                return std::atomic_compare_exchange_strong(obj, expected, desired);
#else
                return std::atomic_compare_exchange_weak(obj, expected, desired);
#endif
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil