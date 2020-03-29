//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/detail/blocking_behavior.hpp>

namespace nil::actor::detail {

    blocking_behavior::~blocking_behavior() {
        // nop
    }

    blocking_behavior::blocking_behavior(behavior &x) : nested(x) {
        // nop
    }

    result<message> blocking_behavior::fallback(message &) {
        return skip;
    }

    timespan blocking_behavior::timeout() {
        return infinite;
    }

    void blocking_behavior::handle_timeout() {
        // nop
    }

}    // namespace nil::actor::detail