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

#include <nil/actor/uniform_type_info_map.hpp>

#include <ios>    // std::ios_base::failure
#include <array>
#include <tuple>
#include <limits>
#include <string>
#include <vector>
#include <cstring>    // memcmp
#include <algorithm>
#include <type_traits>

#include <nil/actor/abstract_group.hpp>
#include <nil/actor/actor_cast.hpp>
#include <nil/actor/actor_factory.hpp>
#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/downstream_msg.hpp>
#include <nil/actor/duration.hpp>
#include <nil/actor/group.hpp>
#include <nil/actor/locks.hpp>
#include <nil/actor/logger.hpp>
#include <nil/actor/message.hpp>
#include <nil/actor/message_builder.hpp>
#include <nil/actor/proxy_registry.hpp>
#include <nil/actor/string_algorithms.hpp>
#include <nil/actor/timespan.hpp>
#include <nil/actor/timestamp.hpp>
#include <nil/actor/type_nr.hpp>
#include <nil/actor/upstream_msg.hpp>

#include <nil/actor/detail/safe_equal.hpp>
#include <nil/actor/detail/scope_guard.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        const char *numbered_type_names[] = {"@actor",
                                             "@actorvec",
                                             "@addr",
                                             "@addrvec",
                                             "@atom",
                                             "@bytebuf",
                                             "@charbuf",
                                             "@config_value",
                                             "@down",
                                             "@downstream_msg",
                                             "@duration",
                                             "@error",
                                             "@exit",
                                             "@group",
                                             "@group_down",
                                             "@i16",
                                             "@i32",
                                             "@i64",
                                             "@i8",
                                             "@ldouble",
                                             "@message",
                                             "@message_id",
                                             "@node",
                                             "@open_stream_msg",
                                             "@str",
                                             "@strmap",
                                             "@strong_actor_ptr",
                                             "@strset",
                                             "@strvec",
                                             "@timeout",
                                             "@timespan",
                                             "@timestamp",
                                             "@u16",
                                             "@u16str",
                                             "@u32",
                                             "@u32str",
                                             "@u64",
                                             "@u8",
                                             "@unit",
                                             "@upstream_msg",
                                             "@weak_actor_ptr",
                                             "bool",
                                             "double",
                                             "float"};

        namespace {

            using builtins = std::array<uniform_type_info_map::value_factory_kvp, type_nrs - 1>;

            void fill_builtins(builtins &, detail::type_list<>, size_t) {
                // end of recursion
            }

            template<class List>
            void fill_builtins(builtins &arr, List, size_t pos) {
                using type = typename detail::tl_head<List>::type;
                typename detail::tl_tail<List>::type next;
                arr[pos].first = numbered_type_names[pos];
                arr[pos].second = &make_type_erased_value<type>;
                fill_builtins(arr, next, pos + 1);
            }

        }    // namespace

        type_erased_value_ptr uniform_type_info_map::make_value(uint16_t nr) const {
            return builtin_[nr - 1].second();
        }

        type_erased_value_ptr uniform_type_info_map::make_value(const std::string &x) const {
            auto pred = [&](const value_factory_kvp &kvp) { return kvp.first == x; };
            auto e = builtin_.end();
            auto i = std::find_if(builtin_.begin(), e, pred);
            if (i != e)
                return i->second();
            auto &custom_names = system().config().value_factories_by_name;
            auto j = custom_names.find(x);
            if (j != custom_names.end())
                return j->second();
            return nullptr;
        }

        type_erased_value_ptr uniform_type_info_map::make_value(const std::type_info &x) const {
            auto &custom_by_rtti = system().config().value_factories_by_rtti;
            auto i = custom_by_rtti.find(std::type_index(x));
            if (i != custom_by_rtti.end())
                return i->second();
            return nullptr;
        }

        const std::string &uniform_type_info_map::portable_name(uint16_t nr, const std::type_info *ti) const {
            if (nr != 0)
                return builtin_names_[nr - 1];
            if (ti == nullptr)
                return default_type_name_;
            auto &custom_names = system().config().type_names_by_rtti;
            auto i = custom_names.find(std::type_index(*ti));
            if (i != custom_names.end())
                return i->second;
            return default_type_name_;
        }

        uniform_type_info_map::uniform_type_info_map(spawner &sys) : system_(sys), default_type_name_("???") {
            sorted_builtin_types list;
            fill_builtins(builtin_, list, 0);
            for (size_t i = 0; i < builtin_names_.size(); ++i)
                builtin_names_[i] = numbered_type_names[i];
        }

    }    // namespace actor
}    // namespace nil
