//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <atomic>
#include <cstddef>

#include <boost/config.hpp>

namespace nil::actor::detail {

    /// A spinlock implementation providing shared and exclusive locking.
    class BOOST_SYMBOL_VISIBLE shared_spinlock {
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

    private:
        std::atomic<long> flag_;
    };

}    // namespace nil::actor::detail