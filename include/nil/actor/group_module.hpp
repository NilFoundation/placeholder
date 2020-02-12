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

#pragma once

#include <string>
#include <memory>

#include <nil/actor/fwd.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/attachable.hpp>
#include <nil/actor/ref_counted.hpp>
#include <nil/actor/abstract_channel.hpp>

namespace nil {
    namespace actor {

        /// Interface for user-defined multicast implementations.
        class group_module {
        public:
            // -- constructors, destructors, and assignment operators --------------------

            group_module(spawner &sys, std::string mname);

            virtual ~group_module();

            // -- pure virtual member functions ------------------------------------------

            /// Stops all groups from this module.
            virtual void stop() = 0;

            /// Returns a pointer to the group associated with the name `group_name`.
            /// @threadsafe
            virtual expected<group> get(const std::string &group_name) = 0;

            /// Loads a group of this module from `source` and stores it in `storage`.
            virtual error load(deserializer &source, group &storage) = 0;

            /// Loads a group of this module from `source` and stores it in `storage`.
            virtual error_code<sec> load(binary_deserializer &source, group &storage) = 0;

            // -- observers --------------------------------------------------------------

            /// Returns the hosting actor system.
            inline spawner &system() const {
                return system_;
            }

            /// Returns the name of this module implementation.
            inline const std::string &name() const {
                return name_;
            }

        private:
            spawner &system_;
            std::string name_;
        };
    }    // namespace actor
}    // namespace nil
