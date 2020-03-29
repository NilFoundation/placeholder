//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/actor_clock.hpp>

namespace nil {
    namespace actor {

        // -- constructors, destructors, and assignment operators ----------------------

        actor_clock::~actor_clock() {
            // nop
        }

        // -- observers ----------------------------------------------------------------

        actor_clock::time_point actor_clock::now() const noexcept {
            return clock_type::now();
        }

    }    // namespace actor
}    // namespace nil
