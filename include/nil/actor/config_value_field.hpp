//---------------------------------------------------------------------------//
// Copyright (c) 2011-2019 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#pragma once

#include <nil/actor/fwd.hpp>
#include <nil/actor/parser_state.hpp>

namespace nil {
    namespace actor {

        /// Describes a field of `Object`.
        template<class Object>
        class config_value_field {
        public:
            using object_type = Object;

            virtual ~config_value_field() = default;

            // -- observers --------------------------------------------------------------

            /// Returns whether this field has a default value.
            virtual bool has_default() const noexcept = 0;

            /// Returns the name of this field.
            virtual string_view name() const noexcept = 0;

            /// Returns the value of this field in `object` as config value.
            virtual config_value get(const Object &object) const = 0;

            /// Returns whether calling `set` with `x` would succeed.
            virtual bool valid_input(const config_value &x) const = 0;

            // -- modifiers --------------------------------------------------------------

            /// Tries to set this field in `object` to `x`.
            /// @returns `true` on success, `false` otherwise.
            virtual bool set(Object &object, const config_value &x) const = 0;

            /// Restores the default value for this field in `object`.
            /// @pre `has_default()`
            virtual void set_default(Object &object) const = 0;

            /// Parses the content for this field in `object` from `ps`.
            virtual void parse_cli(string_parser_state &ps, Object &object, const char *char_blacklist = "") const = 0;
        };

    }    // namespace actor
}    // namespace nil
