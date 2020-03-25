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

#include <nil/actor/detail/set_thread_name.hpp>

#include <nil/actor/config.hpp>

#ifndef ACTOR_WINDOWS
#include <pthread.h>
#endif    // ACTOR_WINDOWS

#if defined(ACTOR_LINUX)
#include <sys/prctl.h>
#elif defined(ACTOR_BSD)
#include <pthread_np.h>
#endif    // defined(...)

#include <thread>
#include <type_traits>

namespace nil {
    namespace actor {
        namespace detail {

            void set_thread_name(const char *name) {
                ACTOR_IGNORE_UNUSED(name);
#ifdef ACTOR_WINDOWS
                // nop
#else    // ACTOR_WINDOWS
                static_assert(std::is_same<std::thread::native_handle_type, pthread_t>::value,
                              "std::thread not based on pthread_t");
#if defined(ACTOR_MACOS)
                pthread_setname_np(name);
#elif defined(ACTOR_LINUX)
                prctl(PR_SET_NAME, name, 0, 0, 0);
#elif defined(ACTOR_BSD)
                pthread_set_name_np(pthread_self(), name);
#endif    // defined(...)
#endif    // ACTOR_WINDOWS
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
