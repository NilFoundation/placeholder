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

#include <vector>

#include <nil/actor/actor_addr.hpp>
#include <nil/actor/mailbox_element.hpp>
#include <nil/actor/monitorable_actor.hpp>

namespace nil::actor::decorator {

    /// An actor decorator implementing "dot operator"-like compositions,
    /// i.e., `f.g(x) = f(g(x))`. Composed actors are hidden actors.
    /// A composed actor exits when either of its constituent actors exits;
    /// Constituent actors have no dependency on the composed actor
    /// by default, and exit of a composed actor has no effect on its
    /// constituent actors. A composed actor is hosted on the same actor
    /// system and node as `g`, the first actor on the forwarding chain.
    class BOOST_SYMBOL_VISIBLE splitter : public monitorable_actor {
    public:
        using message_types_set = std::set<std::string>;

        splitter(std::vector<strong_actor_ptr> workers, message_types_set msg_types);

        // non-system messages are processed and then forwarded;
        // system messages are handled and consumed on the spot;
        // in either case, the processing is done synchronously
        void enqueue(mailbox_element_ptr what, execution_unit *context) override;

        message_types_set message_types() const override;

    private:
        const size_t num_workers;
        std::vector<strong_actor_ptr> workers_;
        message_types_set msg_types_;
    };

}    // namespace nil::actor::decorator
