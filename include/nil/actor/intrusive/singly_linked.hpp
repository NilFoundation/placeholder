//---------------------------------------------------------------------------//
// Copyright (c) 2011-2017 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

namespace nil::actor::intrusive {

    /// Intrusive base for singly linked types that allows queues to use `T` with
    /// dummy nodes.
    template<class T>
    struct singly_linked {
        // -- member types -----------------------------------------------------------

        /// The type for dummy nodes in singly linked lists.
        using node_type = singly_linked<T>;

        /// Type of the pointer connecting two singly linked nodes.
        using node_pointer = node_type *;

        // -- constructors, destructors, and assignment operators --------------------

        singly_linked(node_pointer n = nullptr) : next(n) {
            // nop
        }

        // -- member variables -------------------------------------------------------

        /// Intrusive pointer to the next element.
        node_pointer next;
    };

}    // namespace nil::actor::intrusive