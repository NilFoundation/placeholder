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

#include <nil/actor/scoped_execution_unit.hpp>

#include <nil/actor/spawner.hpp>
#include <nil/actor/scheduler/abstract_coordinator.hpp>

namespace nil {
    namespace actor {

        scoped_execution_unit::~scoped_execution_unit() {
            // nop
        }

        void scoped_execution_unit::exec_later(resumable *ptr) {
            system().scheduler().enqueue(ptr);
        }

    }    // namespace actor
}    // namespace nil
