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

#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <nil/actor/fwd.hpp>
#include <nil/actor/optional.hpp>
#include <nil/actor/expected.hpp>
#include <nil/actor/group_module.hpp>
#include <nil/actor/abstract_group.hpp>
#include <nil/actor/detail/shared_spinlock.hpp>

namespace nil {
    namespace actor {

        class group_manager {
        public:
            // -- friends ----------------------------------------------------------------

            friend class spawner;

            // -- member types -----------------------------------------------------------

            using modules_map = std::unordered_map<std::string, std::unique_ptr<group_module>>;

            // -- constructors, destructors, and assignment operators --------------------

            ~group_manager();

            // -- observers --------------------------------------------------------------

            /// Get a handle to the group associated with given URI scheme.
            /// @threadsafe
            /// @experimental
            expected<group> get(std::string group_uri) const;

            /// Get a handle to the group associated with
            /// `identifier` from the module `mod_name`.
            /// @threadsafe
            expected<group> get(const std::string &module_name, const std::string &group_identifier) const;

            /// Get a pointer to the group associated with
            /// `identifier` from the module `local`.
            /// @threadsafe
            group get_local(const std::string &group_identifier) const;

            /// Returns an anonymous group.
            /// Each calls to this member function returns a new instance
            /// of an anonymous group. Anonymous groups can be used whenever
            /// a set of actors wants to communicate using an exclusive channel.
            group anonymous() const;

            /// Returns the module named `name` if it exists, otherwise `none`.
            optional<group_module &> get_module(const std::string &x) const;

        private:
            // -- constructors, destructors, and assignment operators --------------------

            group_manager(spawner &sys);

            // -- member functions required by spawner ------------------------------

            void init(spawner_config &cfg);

            void start();

            void stop();

            // -- data members -----------------------------------------------------------

            modules_map mmap_;
            spawner &system_;
        };

    }    // namespace actor
}    // namespace nil
