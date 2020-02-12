//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {

        /// Interface to define thread hooks.
        class thread_hook {
        public:
            virtual ~thread_hook();

            /// Called by the actor system once before starting any threads.
            virtual void init(spawner &) = 0;

            /// Called whenever the actor system has started a new thread.
            /// To access a reference to the started thread use `std::this_thread`.
            /// @warning must the thread-safe
            virtual void thread_started() = 0;

            /// Called whenever a thread is about to quit.
            /// To access a reference to the terminating thread use `std::this_thread`.
            /// @warning must the thread-safe
            virtual void thread_terminates() = 0;
        };

    }    // namespace actor
}    // namespace nil
