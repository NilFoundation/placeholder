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

#pragma once

#include <set>
#include <map>
#include <string>
#include <utility>
#include <typeinfo>
#include <stdexcept>
#include <typeindex>
#include <type_traits>
#include <unordered_map>

#include <nil/actor/fwd.hpp>

#include <nil/actor/atom.hpp>
#include <nil/actor/unit.hpp>
#include <nil/actor/node_id.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/system_messages.hpp>
#include <nil/actor/type_erased_value.hpp>

#include <nil/actor/type_nr.hpp>
#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        class uniform_type_info_map {
        public:
            friend class spawner;

            using value_factory = std::function<type_erased_value_ptr()>;

            using actor_factory_result = std::pair<strong_actor_ptr, std::set<std::string>>;

            using actor_factory = std::function<actor_factory_result(actor_config &, message &)>;

            using actor_factories = std::unordered_map<std::string, actor_factory>;

            using value_factories_by_name = std::unordered_map<std::string, value_factory>;

            using value_factories_by_rtti = std::unordered_map<std::type_index, value_factory>;

            using value_factory_kvp = std::pair<std::string, value_factory>;

            using portable_names = std::unordered_map<std::type_index, std::string>;

            using error_renderer = std::function<std::string(uint8_t, atom_value, const message &)>;

            using error_renderers = std::unordered_map<atom_value, error_renderer>;

            type_erased_value_ptr make_value(uint16_t nr) const;

            type_erased_value_ptr make_value(const std::string &x) const;

            type_erased_value_ptr make_value(const std::type_info &x) const;

            /// Returns the portable name for given type information or `nullptr`
            /// if no mapping was found.
            const std::string &portable_name(uint16_t nr, const std::type_info *ti) const;

            /// Returns the portable name for given type information or `nullptr`
            /// if no mapping was found.
            const std::string &portable_name(const std::pair<uint16_t, const std::type_info *> &x) const {
                return portable_name(x.first, x.second);
            }

            /// Returns the enclosing actor system.
            spawner &system() const {
                return system_;
            }

            /// Returns the default type name for unknown types.
            const std::string &default_type_name() const {
                return default_type_name_;
            }

        private:
            uniform_type_info_map(spawner &sys);

            /// Reference to the parent system.
            spawner &system_;

            /// Value factories for builtin types.
            std::array<value_factory_kvp, type_nrs - 1> builtin_;

            /// Values factories for user-defined types.
            value_factories_by_name ad_hoc_;

            /// Lock for accessing `ad_hoc_`.`
            mutable detail::shared_spinlock ad_hoc_mtx_;

            /// Names of builtin types.
            std::array<std::string, type_nrs - 1> builtin_names_;

            /// Displayed name for unknown types.
            std::string default_type_name_;
        };

    }    // namespace actor
}    // namespace nil
