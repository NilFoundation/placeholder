//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt for Boost License or
// http://opensource.org/licenses/BSD-3-Clause for BSD 3-Clause License
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <mutex>
#include <condition_variable>

#include <nil/actor/fwd.hpp>

namespace nil {
    namespace actor {
        namespace detail {

            class private_thread {
            public:
                enum worker_state { active, shutdown_requested, await_resume_or_shutdown };

                explicit private_thread(scheduled_actor *self);

                void run();

                bool await_resume();

                void resume();

                void shutdown();

                static void exec(private_thread *this_ptr);

                void notify_self_destroyed();

                void await_self_destroyed();

                void start();

            private:
                std::mutex mtx_;
                std::condition_variable cv_;
                std::atomic<bool> self_destroyed_;
                std::atomic<scheduled_actor *> self_;
                std::atomic<worker_state> state_;
                spawner &system_;
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
