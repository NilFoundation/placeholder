//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <string>
#include <tuple>

#include <nil/actor/detail/stringification_inspector.hpp>

namespace nil {
    namespace actor {

        /// Unrolls collections such as vectors/maps, decomposes
        /// tuples/pairs/arrays, auto-escapes strings and calls
        /// `to_string` for user-defined types via argument-dependent
        /// loopkup (ADL). Any user-defined type that does not
        /// provide a `to_string` is mapped to `<unprintable>`.
        template<class... Ts>
        std::string deep_to_string(const Ts &... xs) {
            std::string result;
            detail::stringification_inspector f {result};
            f(xs...);
            return result;
        }

        struct deep_to_string_t {
            using result_type = std::string;

            static constexpr bool reads_state = true;

            static constexpr bool writes_state = false;

            template<class... Ts>
            result_type operator()(const Ts &... xs) const {
                return deep_to_string(xs...);
            }
        };

        /// Convenience function for `deep_to_string(std::forward_as_tuple(xs...))`.
        template<class... Ts>
        std::string deep_to_string_as_tuple(const Ts &... xs) {
            return deep_to_string(std::forward_as_tuple(xs...));
        }

    }    // namespace actor
}    // namespace nil
