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

#include <string>

#include <nil/actor/detail/comparable.hpp>

namespace nil {
    namespace actor {

        /// Represents "nothing", e.g., for clearing an `optional` by assigning `none`.
        struct none_t : detail::comparable<none_t> {
            constexpr none_t() {
                // nop
            }
            constexpr explicit operator bool() const {
                return false;
            }

            static constexpr int compare(none_t) {
                return 0;
            }
        };

        static constexpr none_t none = none_t {};

        /// @relates none_t
        inline std::string to_string(const none_t &) {
            return "none";
        }

    }    // namespace actor
}    // namespace nil
