//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/actor_proxy.hpp>

namespace nil {
    namespace actor {

        actor_proxy::actor_proxy(actor_config &cfg) : monitorable_actor(cfg) {
            // nop
        }

        actor_proxy::~actor_proxy() {
            // nop
        }

    }    // namespace actor
}    // namespace nil
