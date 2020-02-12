//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt or
// http://opensource.org/licenses/BSD-3-Clause
//---------------------------------------------------------------------------//

#include <nil/actor/runtime_settings_map.hpp>

#include <nil/actor/locks.hpp>

namespace {

    using mapped_type = nil::actor::runtime_settings_map::mapped_type;

}    // namespace

namespace nil {
    namespace actor {

        mapped_type runtime_settings_map::get(atom_value key) const {
            mapped_type fallback;
            return get_or(key, fallback);
        }

        mapped_type runtime_settings_map::get_or(atom_value key, mapped_type fallback) const {
            shared_lock<mutex_type> guard {mtx_};
            auto i = map_.find(key);
            return i != map_.end() ? i->second : fallback;
        }

        void runtime_settings_map::set(atom_value key, mapped_type value) {
            if (holds_alternative<none_t>(value)) {
                erase(key);
                return;
            }
            unique_lock<mutex_type> guard {mtx_};
            auto res = map_.emplace(key, value);
            if (!res.second)
                res.first->second = value;
        }

        void runtime_settings_map::erase(atom_value key) {
            unique_lock<mutex_type> guard {mtx_};
            map_.erase(key);
        }

        size_t runtime_settings_map::size() const {
            shared_lock<mutex_type> guard {mtx_};
            return map_.size();
        }

    }    // namespace actor
}    // namespace nil
