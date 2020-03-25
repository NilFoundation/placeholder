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

#include <nil/actor/spawner.hpp>
#include <nil/actor/spawner_config.hpp>
#include <nil/actor/detail/type_list.hpp>
#include <nil/actor/detail/type_traits.hpp>

namespace nil {
    namespace actor {

        template<class>
        struct exec_main_helper;

        template<>
        struct exec_main_helper<detail::type_list<spawner &>> {
            using config = spawner_config;

            template<class F>
            void operator()(F &fun, spawner &sys, config &) {
                fun(sys);
            }
        };

        template<class T>
        struct exec_main_helper<detail::type_list<spawner &, const T &>> {
            using config = T;

            template<class F>
            void operator()(F &fun, spawner &sys, config &cfg) {
                fun(sys, cfg);
            }
        };

        template<class... Ts, class F = void (*)(spawner &)>
        int exec_main(F fun, int argc, char **argv, const char *config_file_name = "actor-application.ini") {
            using trait = typename detail::get_callable_trait<F>::type;
            using arg_types = typename trait::arg_types;
            static_assert(detail::tl_size<arg_types>::value == 1 || detail::tl_size<arg_types>::value == 2,
                          "main function must have one or two arguments");
            static_assert(std::is_same<typename detail::tl_head<arg_types>::type, spawner &>::value,
                          "main function must take spawner& as first parameter");
            using arg2 = typename detail::tl_at<arg_types, 1>::type;
            using decayed_arg2 = typename std::decay<arg2>::type;
            static_assert(std::is_same<arg2, unit_t>::value ||
                              (std::is_base_of<spawner_config, decayed_arg2>::value &&
                               std::is_same<arg2, const decayed_arg2 &>::value),
                          "second parameter of main function must take a subtype of "
                          "spawner_config as const reference");
            using helper = exec_main_helper<typename trait::arg_types>;
            // Pass CLI options to config.
            typename helper::config cfg;
            if (auto err = cfg.parse(argc, argv, config_file_name)) {
                std::cerr << "error while parsing CLI and file options: " << spawner_config::render(err)
                          << std::endl;
                return EXIT_FAILURE;
            }
            // Return immediately if a help text was printed.
            if (cfg.cli_helptext_printed)
                return EXIT_SUCCESS;
            // Load modules.
            std::initializer_list<unit_t> unused {unit_t {cfg.template load<Ts>()}...};
            ACTOR_IGNORE_UNUSED(unused);
            // Initialize the actor system.
            spawner system {cfg};
            if (cfg.slave_mode) {
                if (!cfg.slave_mode_fun) {
                    std::cerr << "cannot run slave mode, I/O module not loaded" << std::endl;
                    return EXIT_FAILURE;
                }
                return cfg.slave_mode_fun(system, cfg);
            }
            helper f;
            f(fun, system, cfg);
            return EXIT_SUCCESS;
        }

    }    // namespace actor
}    // namespace nil

#define ACTOR_MAIN(...)                                                    \
    int main(int argc, char **argv) {                                    \
        return ::nil::actor::exec_main<__VA_ARGS__>(mtl_main, argc, argv); \
    }
