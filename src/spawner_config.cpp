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

#include <nil/actor/spawner_config.hpp>

#include <limits>
#include <thread>
#include <fstream>
#include <sstream>

#include <boost/math/common_factor_rt.hpp>

#include <nil/actor/config.hpp>
#include <nil/actor/defaults.hpp>
#include <nil/actor/detail/parser/read_string.hpp>
#include <nil/actor/message_builder.hpp>
#include <utility>

namespace nil {
    namespace actor {

        // in this config class, we have (1) hard-coded defaults that are overridden
        // by (2) INI-file contents that are in turn overridden by (3) CLI arguments

        spawner_config::spawner_config() : slave_mode(false), slave_mode_fun(nullptr) {
            // add `vector<T>` and `stream<T>` for each statically known type
            add_message_type_impl<stream<actor>>("stream<@actor>");
            add_message_type_impl<stream<actor_addr>>("stream<@addr>");
            add_message_type_impl<stream<atom_value>>("stream<@atom>");
            add_message_type_impl<stream<message>>("stream<@message>");
            add_message_type_impl<std::vector<actor>>("std::vector<@actor>");
            add_message_type_impl<std::vector<actor_addr>>("std::vector<@addr>");
            add_message_type_impl<std::vector<atom_value>>("std::vector<@atom>");
            add_message_type_impl<std::vector<message>>("std::vector<@message>");
            add_message_type_impl<settings>("settings");
            add_message_type_impl<config_value::list>("std::vector<@config_value>");
            add_message_type_impl<config_value::dictionary>("dictionary<@config_value>");
            // (1) hard-coded defaults
            stream_desired_batch_complexity = defaults::stream::desired_batch_complexity;
            stream_max_batch_delay = defaults::stream::max_batch_delay;
            stream_credit_round_interval = defaults::stream::credit_round_interval;
            // fill our options vector for creating INI and CLI parsers
            error_renderers.emplace(atom("system"), render_sec);
            error_renderers.emplace(atom("exit"), render_exit_reason);
        }

        spawner_config &spawner_config::add_actor_factory(std::string name, actor_factory fun) {
            actor_factories.emplace(std::move(name), std::move(fun));
            return *this;
        }

        spawner_config &spawner_config::add_error_category(atom_value x, error_renderer y) {
            error_renderers[x] = std::move(y);
            return *this;
        }

        timespan spawner_config::stream_tick_duration() const noexcept {
            auto ns_count = boost::math::gcd(stream_credit_round_interval.count(), stream_max_batch_delay.count());
            return timespan {ns_count};
        }
        std::string spawner_config::render(const error &err) {
            switch (static_cast<uint64_t>(err.category())) {
                case atom_uint("system"):
                    return render_sec(err.code(), err.category(), err.context());
                case atom_uint("exit"):
                    return render_exit_reason(err.code(), err.category(), err.context());
                case atom_uint("parser"):
                    return render_pec(err.code(), err.category(), err.context());
            }
            return "unknown-error";
        }

        std::string spawner_config::render_sec(uint8_t x, atom_value, const message &xs) {
            auto tmp = static_cast<sec>(x);
            return deep_to_string(meta::type_name("system_error"), tmp, meta::omittable_if_empty(), xs);
        }

        std::string spawner_config::render_exit_reason(uint8_t x, atom_value, const message &xs) {
            auto tmp = static_cast<exit_reason>(x);
            return deep_to_string(meta::type_name("exit_reason"), tmp, meta::omittable_if_empty(), xs);
        }

        std::string spawner_config::render_pec(uint8_t x, atom_value, const message &xs) {
            auto tmp = static_cast<pec>(x);
            return deep_to_string(meta::type_name("parser_error"), tmp, meta::omittable_if_empty(), xs);
        }

        const settings &content(const spawner_config &cfg) {
            return cfg.content;
        }

    }    // namespace actor
}    // namespace nil
