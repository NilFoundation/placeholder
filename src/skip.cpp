//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#include <nil/actor/skip.hpp>

#include <nil/actor/result.hpp>
#include <nil/actor/message.hpp>

namespace nil {
    namespace actor {

        result<message> skip_t::skip_fun_impl(scheduled_actor *, message_view &) {
            return skip();
        }

        skip_t::operator fun() const {
            return skip_fun_impl;
        }

    }    // namespace actor
}    // namespace nil
