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

#include <functional>
#include <type_traits>

#include <boost/config.hpp>

#include <nil/actor/timespan.hpp>

namespace nil {
    namespace actor {

        namespace detail {

            class behavior_impl;

            BOOST_SYMBOL_VISIBLE behavior_impl *new_default_behavior(timespan d, std::function<void()> fun);

        }    // namespace detail

        template<class F>
        struct timeout_definition {
            static constexpr bool may_have_timeout = true;

            timespan timeout;

            F handler;

            detail::behavior_impl *as_behavior_impl() const {
                return detail::new_default_behavior(timeout, handler);
            }

            timeout_definition() = default;
            timeout_definition(timeout_definition &&) = default;
            timeout_definition(const timeout_definition &) = default;

            timeout_definition(timespan timeout, F &&f) : timeout(timeout), handler(std::move(f)) {
                // nop
            }

            template<class U>
            timeout_definition(const timeout_definition<U> &other) : timeout(other.timeout), handler(other.handler) {
                // nop
            }
        };

        template<class T>
        struct is_timeout_definition : std::false_type {};

        template<class T>
        struct is_timeout_definition<timeout_definition<T>> : std::true_type {};

        using generic_timeout_definition = timeout_definition<std::function<void()>>;

    }    // namespace actor
}    // namespace nil
