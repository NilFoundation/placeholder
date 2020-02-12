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

#pragma once

#include <atomic>
#include <cstddef>

namespace nil {
    namespace actor {
        namespace detail {

            /// A spinlock implementation providing shared and exclusive locking.
            class shared_spinlock {

                std::atomic<long> flag_;

            public:
                shared_spinlock();

                void lock();
                void unlock();
                bool try_lock();

                void lock_shared();
                void unlock_shared();
                bool try_lock_shared();

                void lock_upgrade();
                void unlock_upgrade();
                void unlock_upgrade_and_lock();
                void unlock_and_lock_upgrade();
            };

        }    // namespace detail
    }        // namespace actor
}    // namespace nil
