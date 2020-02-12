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

#include <nil/actor/sec.hpp>
#include <nil/actor/error.hpp>
#include <nil/actor/make_message.hpp>
#include <nil/actor/message.hpp>

#include <nil/actor/detail/enum_to_string.hpp>

namespace nil {
    namespace actor {

        namespace {

            const char *sec_strings[] = {
                "none",
                "unexpected_message",
                "unexpected_response",
                "request_receiver_down",
                "request_timeout",
                "no_such_group_module",
                "no_actor_published_at_port",
                "unexpected_actor_messaging_interface",
                "state_not_serializable",
                "unsupported_sys_key",
                "unsupported_sys_message",
                "disconnect_during_handshake",
                "cannot_forward_to_invalid_actor",
                "no_route_to_receiving_node",
                "failed_to_assign_scribe_from_handle",
                "failed_to_assign_doorman_from_handle",
                "cannot_close_invalid_port",
                "cannot_connect_to_node",
                "cannot_open_port",
                "network_syscall_failed",
                "invalid_argument",
                "invalid_protocol_family",
                "cannot_publish_invalid_actor",
                "cannot_spawn_actor_from_arguments",
                "end_of_stream",
                "no_context",
                "unknown_type",
                "no_proxy_registry",
                "runtime_error",
                "remote_linking_failed",
                "cannot_add_upstream",
                "upstream_already_exists",
                "invalid_upstream",
                "cannot_add_downstream",
                "downstream_already_exists",
                "invalid_downstream",
                "no_downstream_stages_defined",
                "stream_init_failed",
                "invalid_stream_state",
                "unhandled_stream_error",
                "bad_function_call",
                "feature_disabled",
                "cannot_open_file",
                "socket_invalid",
                "socket_disconnected",
                "socket_operation_failed",
                "unavailable_or_would_block",
                "remote_lookup_failed",
            };

        }    // namespace

        std::string to_string(sec x) {
            return detail::enum_to_string(x, sec_strings);
        }

        error make_error(sec x) {
            return {static_cast<uint8_t>(x), atom("system")};
        }

        error make_error(sec x, message msg) {
            return {static_cast<uint8_t>(x), atom("system"), std::move(msg)};
        }

        error make_error(sec x, std::string msg) {
            return make_error(x, make_message(std::move(msg)));
        }
    }    // namespace actor
}    // namespace nil
