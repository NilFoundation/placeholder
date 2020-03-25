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

#include <nil/actor/exit_reason.hpp>

#include <nil/actor/message.hpp>

#include <nil/actor/detail/enum_to_string.hpp>

namespace nil {
    namespace actor {

        namespace {

            const char *exit_reason_strings[] = {
                "normal", "unhandled_exception",     "unknown",    "out_of_workers", "user_shutdown",
                "kill",   "remote_link_unreachable", "unreachable"};

        }    // namespace

        std::string to_string(exit_reason x) {
            return detail::enum_to_string(x, exit_reason_strings);
        }

        error make_error(exit_reason x) {
            return {static_cast<uint8_t>(x), atom("exit")};
        }

        error make_error(exit_reason x, message context) {
            return {static_cast<uint8_t>(x), atom("exit"), std::move(context)};
        }

    }    // namespace actor
}    // namespace nil
