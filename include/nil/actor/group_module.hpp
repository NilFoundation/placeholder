//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <memory>
#include <string>

#include <nil/actor/abstract_channel.hpp>
#include <nil/actor/actor_addr.hpp>
#include <nil/actor/attachable.hpp>

#include <nil/actor/fwd.hpp>
#include <nil/actor/ref_counted.hpp>

namespace nil {
    namespace actor {

        /// Interface for user-defined multicast implementations.
        class BOOST_SYMBOL_VISIBLE group_module {
        public:
            // -- constructors, destructors, and assignment operators --------------------

            group_module(spawner &sys, std::string mname);

            group_module(const group_module &) = delete;

            group_module &operator=(const group_module &) = delete;

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
