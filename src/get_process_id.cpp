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

#include <nil/actor/detail/get_process_id.hpp>

#include <nil/actor/config.hpp>

#ifdef ACTOR_WINDOWS
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

namespace nil {
    namespace actor {
        namespace detail {

            unsigned get_process_id() {
#ifdef ACTOR_WINDOWS
                return GetCurrentProcessId();
#else
                return static_cast<unsigned>(getpid());
#endif
            }

        }    // namespace detail
    }        // namespace actor
}    // namespace nil