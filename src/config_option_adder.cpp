//---------------------------------------------------------------------------//
// Copyright (c) 2011-2018 Dominik Charousset
// Copyright (c) 2017-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the terms and conditions of the BSD 3-Clause License or
// (at your option) under the terms and conditions of the Boost Software
// License 1.0. See accompanying files LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt.
//---------------------------------------------------------------------------//

#include <nil/actor/config_option_adder.hpp>

#include <nil/actor/config_option_set.hpp>

namespace nil {
    namespace actor {

        config_option_adder::config_option_adder(config_option_set &target, string_view category) :
            xs_(target), category_(category) {
            // nop
        }

        config_option_adder &config_option_adder::add_neg(bool &ref, string_view name, string_view description) {
            return add_impl(make_negated_config_option(ref, category_, name, description));
        }

        config_option_adder &config_option_adder::add_us(size_t &ref, string_view name, string_view description) {
            return add_impl(make_us_resolution_config_option(ref, category_, name, description));
        }

        config_option_adder &config_option_adder::add_ms(size_t &ref, string_view name, string_view description) {
            return add_impl(make_ms_resolution_config_option(ref, category_, name, description));
        }

        config_option_adder &config_option_adder::add_impl(config_option &&opt) {
            xs_.add(std::move(opt));
            return *this;
        }

    }    // namespace actor
}    // namespace nil
