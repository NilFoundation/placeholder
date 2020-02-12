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

        actor_clock::duration_type actor_clock::difference(atom_value, long, time_point t0, time_point t1) const
            noexcept {
            return t1 - t0;
        }

    }    // namespace actor
}    // namespace nil
