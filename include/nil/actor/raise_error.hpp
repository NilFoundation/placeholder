//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/config.hpp>

#ifndef ACTOR_NO_EXCEPTIONS
#include <stdexcept>
#endif

#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/variadic/size.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/overload.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            void log_cstring_error(const char *cstring);

        }    // namespace detail
    }        // namespace actor
}    // namespace nil

#ifdef ACTOR_NO_EXCEPTIONS

#define ACTOR_RAISE_ERROR_IMPL_1(msg)                 \
    do {                                            \
        ::nil::actor::detail::log_cstring_error(msg); \
        ACTOR_CRITICAL(msg);                          \
    } while (false)

#define ACTOR_RAISE_ERROR_IMPL_2(unused, msg) ACTOR_RAISE_ERROR_IMPL_1(msg)

#else    // ACTOR_NO_EXCEPTIONS

#define ACTOR_RAISE_ERROR_IMPL_2(exception_type, msg) \
    do {                                            \
        ::nil::actor::detail::log_cstring_error(msg); \
        throw exception_type(msg);                  \
    } while (false)

#define ACTOR_RAISE_ERROR_IMPL_1(msg) ACTOR_RAISE_ERROR_IMPL_2(std::runtime_error, msg)

#endif    // ACTOR_NO_EXCEPTIONS

#ifdef ACTOR_MSVC

/// Throws an exception if `ACTOR_NO_EXCEPTIONS` is undefined, otherwise calls
/// abort() after printing a given message.
#define ACTOR_RAISE_ERROR(...) \
    BOOST_PP_CAT(BOOST_PP_OVERLOAD(ACTOR_RAISE_ERROR_IMPL_, __VA_ARGS__)(__VA_ARGS__), BOOST_PP_EMPTY())

#else    // ACTOR_MSVC

/// Throws an exception if `ACTOR_NO_EXCEPTIONS` is undefined, otherwise calls
/// abort() after printing a given message.
#define ACTOR_RAISE_ERROR(...) BOOST_PP_OVERLOAD(ACTOR_RAISE_ERROR_IMPL_, __VA_ARGS__)(__VA_ARGS__)

#endif    // ACTOR_MSVC
