//---------------------------------------------------------------------------//
// Copyright (c) 2011-2020 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/init_global_meta_objects.hpp>

#include <nil/actor/actor.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/actor_control_block.hpp>
#include <nil/actor/byte_buffer.hpp>
#include <nil/actor/config_value.hpp>
#include <nil/actor/downstream_msg.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/group.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_id.hpp>
#include <nil/actor/node_id.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/timespan.hpp>
#include <nil/actor/timestamp.hpp>
#include <nil/actor/unit.hpp>
#include <nil/actor/upstream_msg.hpp>
#include <nil/actor/uri.hpp>

namespace nil::actor::core {

    void init_global_meta_objects() {
        nil::actor::init_global_meta_objects<id_block::core_module>();
    }

}    // namespace nil::actor::core

