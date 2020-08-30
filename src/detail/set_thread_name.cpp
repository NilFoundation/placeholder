//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/detail/set_thread_name.hpp>

#include <nil/actor/config.hpp>

#ifndef BOOST_OS_WINDOWS_AVAILABLE
#include <pthread.h>
#endif    // BOOST_OS_WINDOWS_AVAILABLE

#if defined(BOOST_OS_LINUX_AVAILABLE)
#include <sys/prctl.h>
#elif defined(BOOST_OS_BSD_AVAILABLE)
#include <pthread_np.h>
#endif    // defined(...)

#include <thread>
#include <type_traits>

namespace nil {
    namespace actor {
        namespace detail {

            void set_thread_name(const char *name) {
                ACTOR_IGNORE_UNUSED(name);
#ifdef BOOST_OS_WINDOWS_AVAILABLE
                // nop
#else    // BOOST_OS_WINDOWS_AVAILABLE
                static_assert(std::is_same<std::thread::native_handle_type, pthread_t>::value,
                              "std::thread not based on pthread_t");
#if defined(BOOST_OS_MACOS_AVAILABLE)
                pthread_setname_np(name);
#elif defined(BOOST_OS_LINUX_AVAILABLE)
                prctl(PR_SET_NAME, name, 0, 0, 0);
#elif defined(BOOST_OS_BSD_AVAILABLE)
                pthread_set_name_np(pthread_self(), name);
#endif    // defined(...)
#endif    // BOOST_OS_WINDOWS_AVAILABLE
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
