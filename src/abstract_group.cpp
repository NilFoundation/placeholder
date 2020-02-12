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

#include <nil/actor/abstract_group.hpp>

#include <nil/actor/group.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/group_module.hpp>
#include <nil/actor/group_manager.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        abstract_group::abstract_group(group_module &mod, std::string id, node_id nid) :
            abstract_channel(abstract_channel::is_abstract_group_flag), system_(mod.system()), parent_(mod),
            identifier_(std::move(id)), origin_(std::move(nid)) {
            // nop
        }

        abstract_group::~abstract_group() {
            // nop
        }

    }    // namespace actor
}    // namespace nil
