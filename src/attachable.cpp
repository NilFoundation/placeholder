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

#include <nil/actor/attachable.hpp>

namespace nil {
    namespace actor {

        attachable::~attachable() {
            // Avoid recursive cleanup of next pointers because this can cause a stack
            // overflow for long linked lists.
            using std::swap;
            while (next != nullptr) {
                attachable_ptr tmp;
                swap(next->next, tmp);
                swap(next, tmp);
            }
        }

        attachable::token::token(size_t typenr, const void *vptr) : subtype(typenr), ptr(vptr) {
            // nop
        }

        void attachable::actor_exited(const error &, execution_unit *) {
            // nop
        }

        bool attachable::matches(const token &) {
            return false;
        }

    }    // namespace actor
}    // namespace nil
