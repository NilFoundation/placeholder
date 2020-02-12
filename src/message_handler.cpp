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

#include <nil/actor/config.hpp>
#include <nil/actor/message_handler.hpp>

namespace nil {
    namespace actor {

        message_handler::message_handler(impl_ptr ptr) : impl_(std::move(ptr)) {
            // nop
        }

        void message_handler::assign(message_handler what) {
            impl_.swap(what.impl_);
        }

    }    // namespace actor
}    // namespace nil
