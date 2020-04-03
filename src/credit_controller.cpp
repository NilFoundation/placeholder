//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/credit_controller.hpp>

namespace nil {
    namespace actor {

        credit_controller::credit_controller(scheduled_actor *self) : self_(self) {
            // nop
        }

        credit_controller::~credit_controller() {
            // nop
        }

        credit_controller::assignment credit_controller::compute_bridge() {
            return {0, 0};
        }

        int32_t credit_controller::threshold() const noexcept {
            return -1;
        }

    }    // namespace actor
}    // namespace nil
