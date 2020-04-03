//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/detail/get_process_id.hpp>

#include <nil/actor/config.hpp>

#ifdef ACTOR_WINDOWS
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

namespace nil::actor::detail {

    unsigned get_process_id() {
#ifdef ACTOR_WINDOWS
        return GetCurrentProcessId();
#else
        return static_cast<unsigned>(getpid());
#endif
    }

}    // namespace nil::actor::detail