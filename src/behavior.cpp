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

#include <nil/actor/none.hpp>

#include <nil/actor/behavior.hpp>
#include <nil/actor/message_handler.hpp>

namespace nil {
    namespace actor {

        behavior::behavior(const message_handler &mh) : impl_(mh.as_behavior_impl()) {
            // nop
        }

        void behavior::assign(message_handler other) {
            impl_.swap(other.impl_);
        }

        void behavior::assign(behavior other) {
            impl_.swap(other.impl_);
        }

    }    // namespace actor
}    // namespace nil
